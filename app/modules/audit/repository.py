"""Data access for audit. No business rules here."""
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID
from typing import Any
from app.modules.audit.models import AuditLog


class AuditRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(
        self,
        *,
        action: str,
        user_id: UUID | None,
        entity_type: str | None,
        entity_id: UUID | None,
        ip: str | None,
        meta: dict[str, Any],
    ) -> AuditLog:
        """Add an audit log entry."""
        audit_log = AuditLog(
            action=action,
            user_id=user_id,
            entity_type=entity_type,
            entity_id=entity_id,
            ip=ip,
            meta=meta
        )

        self._session.add(audit_log)
        await self._session.flush()
        return audit_log