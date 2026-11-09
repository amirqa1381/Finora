from functools import lru_cache
from typing import Literal

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # hide_input_in_errors: a startup validation error must not print the offending
    # value (it could be a nearly-valid real secret) into the console or logs.
    model_config = SettingsConfigDict(
        env_file=".env", extra="ignore", hide_input_in_errors=True
    )

    app_name: str = "Finora"
    # Literal: a typo such as ENVIRONMENT=prod fails at startup instead of
    # silently skipping every `if environment == "production"` check.
    environment: Literal["local", "test", "staging", "production"] = "local"
    debug: bool = False

    database_url: str = "postgresql+asyncpg://finora:finora@db:5432/finora"
    redis_url: str = "redis://redis:6379/0"

    # No default on purpose: if JWT_SECRET is missing the app must refuse to
    # start, not sign tokens with a secret that anyone reading the repo knows.
    # The signing algorithm (HS256) is a constant in core/security.py, not a setting.
    jwt_secret: SecretStr = "ee4b87afcd7a2a09c26983ad99ad15800643418a5b5069a46114f6033a220599"
    access_token_ttl_seconds: int = 15 * 60
    refresh_token_ttl_seconds: int = 30 * 24 * 60 * 60
    login_max_failures: int = 5
    register_max_per_window: int = 5

    # Envelope-encryption master key (Phase 3). Must come from env/KMS, never the DB.
    credentials_master_key: SecretStr | None = None

    log_level: str = "INFO"

    @field_validator("jwt_secret")
    @classmethod
    def _jwt_secret_is_strong(cls, value: SecretStr) -> SecretStr:
        # Never put the value itself in the message: errors end up in logs.
        if len(value.get_secret_value()) < 32:
            raise ValueError("JWT_SECRET must be at least 32 characters")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()