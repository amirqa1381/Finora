"""Request/response schemas for the accounts (authentication) module."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr, field_validator

# Tiny denylist for Phase 1. Later this can be loaded from a file of the most
# common leaked passwords (e.g. top 10k) without changing the schema's shape.
_COMMON_PASSWORDS = frozenset(
    {
        "password1234",
        "password12345",
        "passwordpassword",
        "123456789012",
        "1234567890123",
        "qwertyuiop12",
        "qwertyuiopas",
        "iloveyou1234",
        "letmein12345",
        "administrator",
        "welcome12345",
        "changeme1234",
    }
)


class RegisterRequest(BaseModel):
    # Unknown fields are an error, not silently ignored: this blocks "mass
    # assignment" attempts such as {"is_active": true, "is_admin": true}.
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    # SecretStr: repr()/str()/model_dump() show "**********", so the password
    # cannot leak by accident through log.info(req=req) or a debug print.
    # Read the real value only where it is needed: `.get_secret_value()`.
    password: SecretStr = Field(min_length=12, max_length=128)

    @field_validator("email", mode="before")
    @classmethod
    def _normalize_email(cls, value: object) -> object:
        # Runs BEFORE EmailStr validation. EmailStr lowercases only the domain
        # part; we need the whole address lowercased so "Alice@x.com" and
        # "alice@x.com" are the same account (the DB index uses lower(email)).
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("password")
    @classmethod
    def _check_password_policy(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        # Never strip/modify the password itself: leading/trailing spaces are
        # legitimate characters. We only reject an all-whitespace password.
        if not raw.strip():
            raise ValueError("password must not be blank")
        if raw.lower() in _COMMON_PASSWORDS:
            raise ValueError("password is too common")
        # Don't put `raw` in the error message: messages end up in responses/logs.
        return value
