from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: Literal["development", "production", "test"] = "development"
    secret_key: SecretStr = Field(min_length=32)
    public_base_url: str = "https://localhost:8443"
    database_url: str = "sqlite+aiosqlite:///./data/app.db"
    redis_url: str = "redis://localhost:6379/0"

    force_https: bool = True
    cookie_secure: bool = True
    session_ttl_minutes: int = 60
    verification_ttl_minutes: int = 15
    verification_max_attempts: int = 5

    mail_backend: Literal["smtp", "console"] = "smtp"
    smtp_host: str = "localhost"
    smtp_port: int = 1025
    smtp_username: str = ""
    smtp_password: SecretStr = SecretStr("")
    smtp_starttls: bool = False
    smtp_use_tls: bool = False
    mail_from: str = "Autoauditoría <no-reply@localhost>"

    hibp_api_key: SecretStr = SecretStr("")
    hibp_user_agent: str = "herramienta-osint-autoauditoria"
    hibp_requests_per_minute: int = Field(default=10, ge=1)
    hibp_max_retries: int = Field(default=4, ge=0)

    result_ttl_seconds: int = 600
    max_upload_bytes: int = 15 * 1024 * 1024
    rate_limit_global_per_minute: int = 120


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
