import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, Index, String, DateTime,func,text, true
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    # The email is the user's identity (there is no separate username).
    # 320 = max length of a valid address. The service stores it lowercased;
    # uniqueness is enforced by the lower(email) index below.
    email: Mapped[str] = mapped_column(String(320))
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())

    settings: Mapped["UserSettings"] = relationship(
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="raise",
    )

    __table_args__ = (Index("uq_users_email_lower", text("lower(email)"), unique=True),)


class UserSettings(TimestampMixin, Base):
    __tablename__ = "user_settings"

    # PK + FK at once => the DB guarantees at most one settings row per user.
    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    locale: Mapped[str] = mapped_column(String(16), default="en", server_default="en")
    timezone: Mapped[str] = mapped_column(String(64), default="UTC", server_default="UTC")
    default_cost_basis: Mapped[str] = mapped_column(String(8), default="FIFO", server_default="FIFO")

    user: Mapped[User] = relationship(back_populates="settings", lazy="raise")

    __table_args__ = (
        CheckConstraint(
            "default_cost_basis IN ('FIFO', 'WAC')",
            name="default_cost_basis_valid",
        ),
    )



class RefreshToken(Base):
    """One row per issued refresh token.

    Rows are never deleted on rotation or logout. A revoked row is exactly how
    we detect reuse: if a revoked token shows up again, someone is replaying
    a stolen token and we revoke all sessions of that user.
    """

    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    # Cross-module link: string table name only, no import of users.models.
    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,  # "revoke all tokens of user X" must be fast
    )
    # SHA-256 hex digest is exactly 64 chars. unique=True also creates the
    # index used for lookup by hash, so no extra index is needed.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # NULL means the token is still active.
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )