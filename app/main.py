from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit, urlunsplit

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import Base, engine, get_db
from app.detection import analyze_event
from app.models import ActivityEvent, Alert, User
from app.schemas import ActivityInput, ActivityOut, AlertOut, RegisterRequest, UserOut
from app.security import create_access_token, decode_access_token, hash_password, verify_password

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan,
              docs_url="/docs" if settings.environment != "production" else None,
              redoc_url=None)
templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            request_bytes = int(content_length)
        except ValueError:
            return Response("Invalid Content-Length", status_code=400)
        if request_bytes < 0:
            return Response("Invalid Content-Length", status_code=400)
        if request_bytes > settings.max_request_bytes:
            return Response("Request too large", status_code=413)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path.startswith("/docs") and settings.environment != "production":
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
    else:
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
    if settings.environment == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    try:
        payload = decode_access_token(token)
        user_id = int(payload["sub"])
    except (jwt.PyJWTError, KeyError, TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    user = db.get(User, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Account unavailable")
    return user


def clean_url(raw: str | None) -> str | None:
    if not raw:
        return None
    try:
        parts = urlsplit(raw)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            return None
        # Strip credentials, query strings, and fragments to avoid retaining secrets.
        hostname = parts.hostname
        if ":" in hostname:
            hostname = f"[{hostname}]"
        netloc = hostname + (f":{parts.port}" if parts.port else "")
        return urlunsplit((parts.scheme.lower(), netloc, parts.path[:1024], "", ""))[:2048]
    except ValueError:
        return None


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse(request, "index.html", {"app_name": settings.app_name})


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "secure-web-activity-monitor"}


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return FileResponse("app/static/favicon.svg", media_type="image/svg+xml")


@app.post("/api/auth/register", response_model=UserOut, status_code=201)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    if not settings.allow_registration and db.scalar(select(func.count(User.id))):
        raise HTTPException(status_code=403, detail="Registration is disabled")
    email = payload.email.lower()
    if db.scalar(select(User.id).where(User.email == email)):
        raise HTTPException(status_code=409, detail="Email is already registered")
    user = User(email=email, display_name=payload.display_name.strip(), password_hash=hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/api/auth/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # OAuth2's standard form uses `username`; accept an email in that field.
    user = db.scalar(select(User).where(User.email == form.username.lower()))
    if not user or not user.is_active or not verify_password(form.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    token = create_access_token(str(user.id))
    return {"access_token": token, "token_type": "bearer", "expires_in": settings.access_token_minutes * 60,
            "user": UserOut.model_validate(user)}


@app.get("/api/auth/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


@app.post("/api/events", response_model=list[ActivityOut], status_code=201)
def ingest_events(payload: ActivityInput | list[ActivityInput], user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    batch = payload if isinstance(payload, list) else [payload]
    if not batch or len(batch) > settings.max_event_batch:
        raise HTTPException(status_code=413, detail=f"Submit between 1 and {settings.max_event_batch} events")
    events = []
    now = datetime.now(timezone.utc)
    for item in batch:
        timestamp = item.occurred_at or now
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        if timestamp > now + timedelta(minutes=5) or timestamp < now - timedelta(days=365):
            raise HTTPException(status_code=422, detail="Event timestamp is outside the accepted range")
        safe_url = clean_url(item.url)
        domain = (item.domain or (urlsplit(safe_url).hostname if safe_url else None) or "")[:253].lower() or None
        event = ActivityEvent(user_id=user.id, occurred_at=timestamp, event_type=item.event_type.lower(),
                              url=safe_url, domain=domain, source_ip=item.source_ip,
                              user_agent=item.user_agent, metadata_json=item.metadata)
        db.add(event)
        db.flush()
        analyze_event(db, event)
        events.append(event)
    db.commit()
    return [ActivityOut.from_orm_event(event) for event in events]


@app.get("/api/events", response_model=list[ActivityOut])
def list_events(limit: int = 50, offset: int = 0, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    limit = min(max(limit, 1), 200)
    rows = db.scalars(select(ActivityEvent).where(ActivityEvent.user_id == user.id)
                      .order_by(ActivityEvent.occurred_at.desc()).offset(max(offset, 0)).limit(limit)).all()
    return [ActivityOut.from_orm_event(row) for row in rows]


@app.get("/api/alerts", response_model=list[AlertOut])
def list_alerts(limit: int = 100, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(Alert).where(Alert.user_id == user.id)
                      .order_by(Alert.created_at.desc()).limit(min(max(limit, 1), 200))).all()
    return rows


@app.post("/api/alerts/{alert_id}/acknowledge", response_model=AlertOut)
def acknowledge_alert(alert_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    alert = db.scalar(select(Alert).where(Alert.id == alert_id, Alert.user_id == user.id))
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_acknowledged = True
    db.commit()
    db.refresh(alert)
    return alert


@app.get("/api/summary")
def summary(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    since = datetime.now(timezone.utc) - timedelta(days=7)
    event_count = db.scalar(select(func.count(ActivityEvent.id)).where(ActivityEvent.user_id == user.id, ActivityEvent.occurred_at >= since)) or 0
    alert_count = db.scalar(select(func.count(Alert.id)).where(Alert.user_id == user.id, Alert.is_acknowledged.is_(False))) or 0
    return {"events_7d": event_count, "open_alerts": alert_count}


@app.delete("/api/events")
def purge_old_events(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.retention_days)
    result = db.query(ActivityEvent).filter(ActivityEvent.user_id == user.id, ActivityEvent.occurred_at < cutoff).delete(synchronize_session=False)
    old_alerts = db.query(Alert).filter(Alert.user_id == user.id, Alert.created_at < cutoff).delete(synchronize_session=False)
    db.commit()
    return {"deleted_events": result, "deleted_alerts": old_alerts}
