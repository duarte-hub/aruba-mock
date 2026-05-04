"""Runtime configuration loaded from environment variables."""
from __future__ import annotations

from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ARUBA_", case_sensitive=False)

    # Storage
    db_path: str = Field(default="/data/aruba.db")

    # HTTP
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8080)

    # Auth
    admin_user: str = Field(default="admin")
    admin_password: str = Field(default="ChangeMe!")
    secret_key: str = Field(default="change-me-to-a-random-string")

    # Poller
    poll_interval: int = Field(default=60, description="Seconds between polls")
    poll_timeout: int = Field(default=5, description="Per-device SNMP/SSH timeout (s)")
    enable_poller: bool = Field(default=True)

    # Logging
    log_level: str = Field(default="info")


@lru_cache
def get_settings() -> Settings:
    return Settings()
