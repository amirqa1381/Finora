from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Finora"
    environment: str = "local"  # local | test | staging | production
    debug: bool = False

    database_url: str = "postgresql+asyncpg://finora:finora@db:5432/finora"
    redis_url: str = "redis://redis:6379/0"

    jwt_secret: SecretStr = Field(default=SecretStr("ee4b87afcd7a2a09c26983ad99ad15800643418a5b5069a46114f6033a220599"))
    jwt_algorithm: str = "HS256"
    access_token_ttl_seconds: int = 15 * 60
    refresh_token_ttl_seconds: int = 30 * 24 * 60 * 60
    login_max_failures: int = 5
    register_max_per_window: int = 5
    

    # Envelope-encryption master key (Phase 3). Must come from env/KMS, never the DB.
    credentials_master_key: SecretStr | None = None

    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    return Settings()
