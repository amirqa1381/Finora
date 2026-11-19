"""Business rules for accounts: register, login, refresh, logout."""

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

import structlog
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.exceptions import AuthenticationError
from app.core.security import (
    create_access_token,
    generate_refresh_token,
    get_dummy_password_hash,
    hash_password,
    hash_refresh_token,
    verify_password,
)
from app.modules.accounts.exceptions import (
    EmailAlreadyRegisteredError,
    InvalidCredentialsError,
    InvalidRefreshTokenError,
)
from app.modules.accounts.models import User
from app.modules.accounts.repository import RefreshTokenRepository, UserRepository
from app.modules.audit.service import AuditService

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str  # raw value: the user gets it once, we store only its hash


class AccountsService:
    def __init__(self, session: AsyncSession, audit: AuditService) -> None:
        self._session = session
        self._audit = audit
        self._users = UserRepository(session)
        self._tokens = RefreshTokenRepository(session)

    # ------------------------------------------------------------ register
    async def register(self, *, email: str, password: str, ip: str | None) -> User:
        email = email.strip().lower()
        password_hash = await asyncio.to_thread(hash_password, password)

        try:
            async with self._session.begin_nested():
                user = await self._users.create(email=email, password_hash=password_hash)
        except IntegrityError:
            raise EmailAlreadyRegisteredError() from None

        await self._audit.record("auth.register", user_id=user.id, ip=ip)
        logger.info("user_registered", user_id=str(user.id))
        return user

    # --------------------------------------------------------------- login
    async def login(self, *, email: str, password: str, ip: str | None) -> TokenPair:
        email = email.strip().lower()
        user = await self._users.get_by_email(email)

        # Always verify exactly once. For an unknown email we verify against a
        # dummy hash, so response time does not reveal whether the email exists.
        hash_to_check = user.password_hash if user else get_dummy_password_hash()
        password_ok = await asyncio.to_thread(verify_password, password, hash_to_check)

        if user is None or not password_ok or not user.is_active:
            # Commit BEFORE raising, otherwise the request rollback erases the row.
            await self._audit.record_and_commit(
                "auth.login.failure",
                user_id=user.id if user else None,
                ip=ip,
            )
            logger.info("login_failed")
            raise InvalidCredentialsError()

        pair = await self._issue_tokens(user.id, now=datetime.now(UTC))
        await self._audit.record("auth.login.success", user_id=user.id, ip=ip)
        logger.info("login_succeeded", user_id=str(user.id))
        return pair

    # ------------------------------------------------------------- refresh
    async def refresh(self, *, refresh_token: str, ip: str | None) -> TokenPair:
        now = datetime.now(UTC)
        # FOR UPDATE: two parallel requests with the same token run one after
        # the other, so the second one sees the token already revoked.
        token = await self._tokens.get_by_hash(
            hash_refresh_token(refresh_token), for_update=True
        )
        if token is None:
            raise InvalidRefreshTokenError()

        if token.revoked_at is not None:
            # A revoked token came back: treat it as stolen.
            # Order matters: revoke all -> audit + commit -> raise.
            await self._tokens.revoke_all_for_user(token.user_id, now=now)
            await self._audit.record_and_commit(
                "auth.refresh.reuse_detected", user_id=token.user_id, ip=ip
            )
            logger.warning("refresh_token_reuse_detected", user_id=str(token.user_id))
            raise InvalidRefreshTokenError()

        if token.expires_at <= now:
            raise InvalidRefreshTokenError()

        user = await self._users.get_by_id(token.user_id)
        if user is None or not user.is_active:
            raise InvalidRefreshTokenError()

        await self._tokens.revoke(token, now=now)
        pair = await self._issue_tokens(user.id, now=now)
        await self._audit.record("auth.refresh.success", user_id=user.id, ip=ip)
        return pair

    # -------------------------------------------------------------- logout
    async def logout(self, *, refresh_token: str, ip: str | None) -> None:
        """Idempotent: an unknown or already revoked token is silently accepted,
        so this endpoint cannot be used to test whether a token exists."""
        token = await self._tokens.get_by_hash(
            hash_refresh_token(refresh_token), for_update=True
        )
        if token is None or token.revoked_at is not None:
            return
        await self._tokens.revoke(token, now=datetime.now(UTC))
        await self._audit.record("auth.logout", user_id=token.user_id, ip=ip)
        logger.info("logout", user_id=str(token.user_id))

    # ----------------------------------------------------------------- me
    async def get_active_user(self, user_id: UUID) -> User:
        user = await self._users.get_by_id(user_id)
        if user is None or not user.is_active:
            raise AuthenticationError("Invalid or missing token")
        return user

    # ------------------------------------------------------------ helpers
    async def _issue_tokens(self, user_id: UUID, *, now: datetime) -> TokenPair:
        raw, token_hash = generate_refresh_token()
        expires_at = now + timedelta(seconds=get_settings().refresh_token_ttl_seconds)
        await self._tokens.add(user_id=user_id, token_hash=token_hash, expires_at=expires_at)
        return TokenPair(access_token=create_access_token(user_id), refresh_token=raw)