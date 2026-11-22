"""Password hashing (Argon2id), access-token JWTs, and opaque refresh tokens.

Crypto for exchange API keys lives in core/crypto.py, not here.

Design rules (see Stage B):
  * Access token  = short-lived, stateless JWT (HS256).
  * Refresh token = random opaque string. Only its SHA-256 hash is stored in the
    DB, so it can be rotated, revoked and reuse-detected. It is NOT a JWT.
"""
from __future__ import annotations

import functools
import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from app.core.config import get_settings

# Hard-coded on purpose: if this came from config, a bad value ("none", an RSA
# algorithm) could silently change what "a valid token" means.
_JWT_ALGORITHM = "HS256"
_ACCESS_TOKEN_TYPE = "access"
# Without "require", PyJWT happily accepts a token that has no `exp` at all
# (i.e. one that never expires).
_REQUIRED_CLAIMS = ["exp", "iat", "sub", "sid","type"]


@dataclass(frozen=True)
class AccessTokenClaims:
    user_id: UUID
    session_id: UUID


class InvalidTokenError(Exception):
    """The access token is malformed, forged, expired, or of the wrong type.

    Callers (deps.get_current_user) catch only this class and never need to
    import jwt. The message is generic on purpose: the reason is not for clients.
    """


# --------------------------------------------------------------------------- passwords
# argon2-cffi's defaults are the RFC 9106 recommended profile and the type is
# Argon2id. Hashing takes tens of milliseconds and blocks the thread, so async
# code should call these via `await asyncio.to_thread(...)`.
_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Return a salted Argon2id hash ("$argon2id$..."). Salt is generated per call."""
    return _hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """True only if `password` matches `hashed`. Never raises.

    A wrong password and a corrupted/garbage hash both return False, so a bad row
    in the DB cannot turn a login attempt into a 500 (which would also be a
    distinguishable response).
    """
    try:
        return _hasher.verify(hashed, password)  # NB: argon2 takes (hash, password)
    except (VerificationError, InvalidHashError):
        return False


@functools.cache
def get_dummy_password_hash() -> str:
    """A valid hash of a random, forgotten password, computed once per process.

    On login with an UNKNOWN email, the service verifies against this hash so the
    request costs as much time as a real wrong-password attempt. Otherwise the
    response time would reveal which emails are registered.
    """
    return _hasher.hash(secrets.token_urlsafe(16))


# --------------------------------------------------------------------------- access tokens
def create_access_token(
    user_id: UUID, *, session_id: UUID, now: datetime | None = None
) -> str:
    settings = get_settings()
    issued_at = now or datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "sid": str(session_id), 
        "type": "access",
        "iat": issued_at,
        "exp": issued_at + timedelta(seconds=settings.access_token_ttl_seconds),
    }
    return jwt.encode(
        payload, settings.jwt_secret.get_secret_value(), algorithm=_JWT_ALGORITHM
    )



def decode_access_token(token: str) -> AccessTokenClaims:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret.get_secret_value(),
            algorithms=[_JWT_ALGORITHM],
            options={"require": _REQUIRED_CLAIMS},
        )
    except jwt.PyJWTError as exc:
        raise InvalidTokenError("invalid access token") from exc

    if payload.get("type") != "access":
        raise InvalidTokenError("wrong token type")

    try:
        return AccessTokenClaims(
            user_id=UUID(payload["sub"]), session_id=UUID(payload["sid"])
        )
    except (ValueError, TypeError, AttributeError) as exc:
        raise InvalidTokenError("invalid claims") from exc

# --------------------------------------------------------------------------- refresh tokens
def hash_refresh_token(raw: str) -> str:
    """Deterministic SHA-256 hex digest, used to look the token up in the DB.

    SHA-256 (not Argon2) is right here: the token already has 256 bits of
    randomness, so there is nothing to brute-force, and we need the same input to
    always give the same hash so `WHERE token_hash = :h` works.
    """
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_refresh_token() -> tuple[str, str]:
    """Return (raw_token, token_hash). Send `raw` to the client, store only the hash."""
    raw = secrets.token_urlsafe(32)  # 32 random bytes -> 43 URL-safe characters
    return raw, hash_refresh_token(raw)