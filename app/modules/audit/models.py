import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Index, String, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AuditLog(Base):
    """Append-only record of sensitive events.

    Never updated or deleted (enforced by a DB trigger, see the second
    migration). No TimestampMixin: there is no updated_at on purpose.
    """

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    # Plain UUID, NO foreign key: failed logins for unknown emails have no
    # user, and a FK with CASCADE/SET NULL would be blocked by the trigger.
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), default=None
    )
    # e.g. "auth.login_success", "auth.login_failure", "auth.logout"
    action: Mapped[str] = mapped_column(String(64))
    # What the event is about (e.g. "user", "portfolio"); null for events
    # with no target, like a login attempt with an unknown email.
    entity_type: Mapped[str | None] = mapped_column(String(64), default=None)
    entity_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), default=None
    )
    # 45 chars = longest textual IPv6 address (including IPv4-mapped form).
    ip: Mapped[str | None] = mapped_column(String(45), default=None)
    # "metadata" is reserved by SQLAlchemy, so the attribute is `meta`
    # and only the DB column is called "metadata".
    # NEVER store passwords, tokens or raw secrets here.
    meta: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        # "Show the recent events of this user" is the main query.
        Index("ix_audit_logs_user_id_created_at", "user_id", "created_at"),
    )