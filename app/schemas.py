from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    display_name: str = Field(min_length=1, max_length=80)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class UserOut(BaseModel):
    id: int
    email: EmailStr
    display_name: str
    model_config = ConfigDict(from_attributes=True)


class ActivityInput(BaseModel):
    occurred_at: datetime | None = None
    event_type: str = Field(default="page_view", min_length=1, max_length=40, pattern=r"^[a-zA-Z0-9_.-]+$")
    url: str | None = Field(default=None, max_length=4096)
    domain: str | None = Field(default=None, max_length=253)
    source_ip: str | None = Field(default=None, max_length=45)
    user_agent: str | None = Field(default=None, max_length=512)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def metadata_size(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(str(value)) > 8000:
            raise ValueError("metadata is too large")
        return value


class ActivityOut(BaseModel):
    id: int
    occurred_at: datetime
    event_type: str
    url: str | None
    domain: str | None
    source_ip: str | None
    user_agent: str | None
    metadata: dict[str, Any]

    @classmethod
    def from_orm_event(cls, event):
        return cls(id=event.id, occurred_at=event.occurred_at, event_type=event.event_type, url=event.url,
                   domain=event.domain, source_ip=event.source_ip, user_agent=event.user_agent,
                   metadata=event.metadata_json or {})


class AlertOut(BaseModel):
    id: int
    rule_key: str
    severity: str
    title: str
    description: str
    score: float | None
    is_acknowledged: bool
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)
