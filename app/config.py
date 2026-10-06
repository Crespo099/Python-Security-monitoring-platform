from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Secure Web Activity Monitor"
    environment: str = "development"
    secret_key: str = "development-only-change-me"
    database_url: str = "sqlite:///./monitor.db"
    access_token_minutes: int = 60
    allow_registration: bool = True
    retention_days: int = 90
    failed_login_threshold: int = 5
    failed_login_window_minutes: int = 10
    activity_burst_threshold: int = 120
    activity_burst_window_minutes: int = 5
    sensitive_paths: str = "/admin,/wp-admin,/login,/account/recovery"
    anomaly_model_enabled: bool = True
    max_event_batch: int = 100
    max_request_bytes: int = 1_048_576

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @model_validator(mode="after")
    def require_production_secret(self):
        key_placeholder = any(word in self.secret_key.lower() for word in ("development", "change-me", "replace-with"))
        if self.environment.lower() == "production" and (key_placeholder or len(self.secret_key) < 32):
            raise ValueError("Set SECRET_KEY to a random value of at least 32 characters in production.")
        return self

    @property
    def sensitive_path_list(self) -> list[str]:
        return [part.strip().lower() for part in self.sensitive_paths.split(",") if part.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
