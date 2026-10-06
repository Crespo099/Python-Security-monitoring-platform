from datetime import datetime, timedelta, timezone

import numpy as np
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import ActivityEvent, Alert


def _alert(db: Session, event: ActivityEvent, key: str, severity: str, title: str, description: str,
           score: float | None = None) -> None:
    # Collapse repeated matches from the same account and rule into one alert per ten minutes.
    alert_since = datetime.now(timezone.utc) - timedelta(minutes=10)
    duplicate = db.scalar(select(Alert.id).where(
        Alert.user_id == event.user_id, Alert.rule_key == key, Alert.created_at >= alert_since
    ).limit(1))
    if duplicate is None:
        db.add(Alert(user_id=event.user_id, event_id=event.id, rule_key=key, severity=severity,
                     title=title, description=description, score=score))


def analyze_event(db: Session, event: ActivityEvent) -> None:
    now = event.occurred_at
    if event.event_type.lower() in {"login_failed", "auth_failed", "failed_login"}:
        start = now - timedelta(minutes=settings.failed_login_window_minutes)
        count = db.scalar(select(func.count(ActivityEvent.id)).where(
            ActivityEvent.user_id == event.user_id, ActivityEvent.event_type.in_(["login_failed", "auth_failed", "failed_login"]),
            ActivityEvent.occurred_at >= start, ActivityEvent.occurred_at <= now)) or 0
        if count >= settings.failed_login_threshold:
            _alert(db, event, "failed_login_burst", "high", "Repeated failed sign-ins",
                   f"{count} failed sign-in events in {settings.failed_login_window_minutes} minutes.")

    path = (event.url or "").lower().split("?", 1)[0]
    if any(pattern in path for pattern in settings.sensitive_path_list):
        _alert(db, event, "sensitive_path", "medium", "Sensitive path visited",
               "An event matched a configured sensitive path pattern.")

    start = now - timedelta(minutes=settings.activity_burst_window_minutes)
    count = db.scalar(select(func.count(ActivityEvent.id)).where(
        ActivityEvent.user_id == event.user_id, ActivityEvent.occurred_at >= start,
        ActivityEvent.occurred_at <= now)) or 0
    if count >= settings.activity_burst_threshold:
        _alert(db, event, "activity_burst", "medium", "Unusually high activity volume",
               f"{count} events in {settings.activity_burst_window_minutes} minutes.")

    if settings.anomaly_model_enabled:
        _anomaly_score(db, event)


_model_cache: dict[int, tuple[int, object]] = {}


def _anomaly_score(db: Session, event: ActivityEvent) -> None:
    # The model uses aggregate numeric features only; it does not learn URL contents.
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError:
        return
    cached = _model_cache.get(event.user_id)
    if cached is None or event.id - cached[0] >= 50:
        rows = db.scalars(select(ActivityEvent).where(ActivityEvent.user_id == event.user_id)
                          .order_by(ActivityEvent.occurred_at.desc()).limit(300)).all()
        if len(rows) < 30:
            return
        features = np.array([[len(r.event_type), r.occurred_at.hour, len(r.url or ""),
                              int(r.event_type in {"login_failed", "auth_failed", "failed_login"})]
                             for r in rows], dtype=float)
        if len(np.unique(features, axis=0)) < 5:
            return
        model = IsolationForest(n_estimators=80, contamination=0.05, random_state=17)
        model.fit(features)
        _model_cache[event.user_id] = (event.id, model)
    else:
        model = cached[1]
    current = np.array([[len(event.event_type), event.occurred_at.hour, len(event.url or ""),
                         int(event.event_type.lower() in {"login_failed", "auth_failed", "failed_login"})]], dtype=float)
    score = float(-model.score_samples(current)[0])
    if model.predict(current)[0] == -1:
        _alert(db, event, "ml_anomaly", "low", "Unusual activity pattern",
               "The optional anomaly model marked this event for review. Verify against known user behavior.", score)
