from collections import Counter, deque
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


def _behavior_features(rows: list[ActivityEvent]) -> np.ndarray:
    features = []
    recent_events: deque[datetime] = deque()
    recent_failures: deque[datetime] = deque()
    event_type_counts: Counter[str] = Counter()
    seen_source_ips: set[str] = set()
    previous_time: datetime | None = None

    for row in rows:
        occurred_at = row.occurred_at
        if occurred_at.tzinfo is None:
            occurred_at = occurred_at.replace(tzinfo=timezone.utc)
        occurred_at = occurred_at.astimezone(timezone.utc)
        event_type = row.event_type.lower()
        is_failed_login = event_type in {"login_failed", "auth_failed", "failed_login"}
        five_minutes_ago = occurred_at - timedelta(minutes=5)
        ten_minutes_ago = occurred_at - timedelta(minutes=10)
        while recent_events and recent_events[0] < five_minutes_ago:
            recent_events.popleft()
        while recent_failures and recent_failures[0] < ten_minutes_ago:
            recent_failures.popleft()

        seconds_since_previous = 3600.0 if previous_time is None else min(
            max((occurred_at - previous_time).total_seconds(), 0.0), 3600.0
        )
        hour_of_week = occurred_at.weekday() * 24 + occurred_at.hour
        angle = 2 * np.pi * hour_of_week / 168
        features.append([
            np.sin(angle),
            np.cos(angle),
            np.log1p(seconds_since_previous),
            np.log1p(len(recent_events)),
            np.log1p(len(recent_failures)),
            float(bool(row.source_ip and row.source_ip not in seen_source_ips)),
            np.log1p(event_type_counts[event_type]),
        ])

        recent_events.append(occurred_at)
        if is_failed_login:
            recent_failures.append(occurred_at)
        event_type_counts[event_type] += 1
        if row.source_ip:
            seen_source_ips.add(row.source_ip)
        previous_time = occurred_at

    return np.asarray(features, dtype=float).reshape((-1, 7))


def _anomaly_score(db: Session, event: ActivityEvent) -> None:
    # The model uses aggregate numeric features only; it does not learn URL contents.
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError:
        return
    cached = _model_cache.get(event.user_id)
    rows = db.scalars(select(ActivityEvent).where(ActivityEvent.user_id == event.user_id)
                      .order_by(ActivityEvent.id.desc()).limit(301)).all()
    rows.reverse()
    rows.sort(key=lambda row: row.occurred_at.replace(tzinfo=timezone.utc)
              if row.occurred_at.tzinfo is None else row.occurred_at.astimezone(timezone.utc))
    if not rows:
        return
    features = _behavior_features(rows)
    current_index = next((index for index, row in enumerate(rows) if row.id == event.id), None)
    if current_index is None:
        return
    training_features = np.delete(features, current_index, axis=0)
    events_since_training = sum(row.id > cached[0] for row in rows) if cached else 0
    if cached is None or events_since_training >= 50:
        if len(training_features) < 30:
            return
        if len(np.unique(training_features, axis=0)) < 5:
            return
        model = IsolationForest(n_estimators=80, contamination=0.05, random_state=17)
        model.fit(training_features)
        _model_cache[event.user_id] = (event.id, model)
    else:
        model = cached[1]
    current = features[current_index:current_index + 1]
    score = float(-model.score_samples(current)[0])
    if model.predict(current)[0] == -1:
        _alert(db, event, "ml_anomaly", "low", "Unusual activity pattern",
               "The optional anomaly model marked this event for review. Verify against known user behavior.", score)
