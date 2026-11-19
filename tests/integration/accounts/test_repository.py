from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.modules.accounts.models import UserSettings
from app.modules.accounts.repository import RefreshTokenRepository, UserRepository

NOW = datetime(2026, 11, 19, tzinfo=UTC)


async def test_create_makes_user_and_settings(db_session):
    user = await UserRepository(db_session).create(email="a@x.com", password_hash="h")
    row = (
        await db_session.execute(select(UserSettings).where(UserSettings.user_id == user.id))
    ).scalar_one()
    assert row.default_cost_basis == "FIFO"


async def test_get_by_email_is_case_insensitive(db_session):
    repo = UserRepository(db_session)
    created = await repo.create(email="a@x.com", password_hash="h")
    found = await repo.get_by_email("A@X.com")
    assert found is not None and found.id == created.id


async def test_duplicate_email_different_case_raises(db_session):
    repo = UserRepository(db_session)
    await repo.create(email="a@x.com", password_hash="h")
    with pytest.raises(IntegrityError):
        await repo.create(email="A@x.com", password_hash="h")


async def test_revoke_all_only_touches_active_tokens_of_that_user(db_session):
    users = UserRepository(db_session)
    tokens = RefreshTokenRepository(db_session)
    u1 = await users.create(email="a@x.com", password_hash="h")
    u2 = await users.create(email="b@x.com", password_hash="h")
    exp = NOW + timedelta(days=7)
    await tokens.add(user_id=u1.id, token_hash="h1", expires_at=exp)
    await tokens.add(user_id=u1.id, token_hash="h2", expires_at=exp)
    await tokens.add(user_id=u2.id, token_hash="h3", expires_at=exp)

    assert await tokens.revoke_all_for_user(u1.id, now=NOW) == 2
    assert (await tokens.get_by_hash("h3")).revoked_at is None