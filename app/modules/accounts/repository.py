"""Data access for accounts. No business rules here."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.accounts.models import RefreshToken, User, UserSettings


class UserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_email(self, email: str) -> User | None:
        """
        Get a user by email. and return None if not found.
        """
        statment = select(User).where(func.lower(User.email) == email.lower())
        result = await self._session.execute(statment)
        return result.scalar_one_or_none()
    

    async def get_by_id(self, user_id: UUID) -> User | None:
        """
        Get a user by id. and return None if not found."""
        statment = select(User).where(User.id == user_id)
        result = await self._session.execute(statment)
        return result.scalar_one_or_none()

    
    async def create(self, *, email: str, password_hash: str) -> User:
        """
        Create a new user with the given email and password hash.
        """

        user = User(email=email, password_hash=password_hash, settings=UserSettings())
        self._session.add(user)
        await self._session.flush()
        return user



class RefreshTokenRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(
        self, *, user_id: UUID, token_hash: str, expires_at: datetime
    ) -> RefreshToken:
        """Add a new refresh token for specified user. The token is not yet revoked."""

        token = RefreshToken(
            user_id=user_id, token_hash=token_hash, expires_at=expires_at
        )
        self._session.add(token)
        await self._session.flush()
        return token

    async def get_by_hash(
        self, token_hash: str, *, for_update: bool = False
    ) -> RefreshToken | None:
        """Get a refresh token by its hash. Return None if not found."""

        statment = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        if for_update == True:
            statment = statment.with_for_update()

        result = await self._session.execute(statment)
        return result.scalar_one_or_none()

    async def revoke(self, token: RefreshToken, *, now: datetime) -> None:
        """Mark the token as revoked. Business checks belong to the service."""
        token.revoked_at = now
        await self._session.flush()

    async def revoke_all_for_user(self, user_id: UUID, *, now: datetime) -> int:
        statement = (
            update(RefreshToken)
            .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        result = await self._session.execute(statement)
        return result.rowcount

        