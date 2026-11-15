"""Business logic for audit. Public interface used by other modules."""
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID
from typing import Any
from app.modules.audit.repository import AuditRepository

class AuditService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._repo = AuditRepository(session)

    async def record(
        self,
        action: str,
        *,
        user_id: UUID | None = None,
        entity_type: str | None = None,
        entity_id: UUID | None = None,
        ip: str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> None: 
        """Record an audit log entry."""

        if meta is None:
            meta = {}

        await self._repo.add(
            action=action,
            user_id=user_id,
            entity_type=entity_type,
            entity_id=entity_id,
            ip=ip,
            meta=meta
        )


    async def record_and_commit(
        self,
        action: str,
        *,
        user_id: UUID | None = None,
        entity_type: str | None = None,
        entity_id: UUID | None = None,
        ip: str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> None:
        """Record an entry and commit immediately.

        Use before raising an error (e.g. failed login), because the request
        rollback would otherwise delete the row.
        """
        await self.record(
            action,
            user_id=user_id,
            entity_type=entity_type,
            entity_id=entity_id,
            ip=ip,
            meta=meta,
        )
        await self._session.commit()