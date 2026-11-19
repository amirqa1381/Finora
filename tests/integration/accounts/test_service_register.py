import pytest
from sqlalchemy import select

from app.core.security import verify_password
from app.modules.accounts.exceptions import EmailAlreadyRegisteredError
from app.modules.accounts.models import User, UserSettings
from app.modules.accounts.service import AccountsService
from app.modules.audit.models import AuditLog
from app.modules.audit.service import AuditService

PASSWORD = "correct-horse-battery-staple"


def make_service(db_session) -> AccountsService:
    return AccountsService(db_session, AuditService(db_session))


async def test_register_stores_hash_not_password(db_session):
    user = await make_service(db_session).register(
        email="  A@X.com ", password=PASSWORD, ip="203.0.113.10"
    )
    assert user.email == "a@x.com"
    assert user.password_hash != PASSWORD
    assert verify_password(PASSWORD, user.password_hash)


async def test_register_creates_settings_row(db_session):
    user = await make_service(db_session).register(email="a@x.com", password=PASSWORD, ip=None)
    row = (
        await db_session.execute(select(UserSettings).where(UserSettings.user_id == user.id))
    ).scalar_one()
    assert row.default_cost_basis == "FIFO"


async def test_register_duplicate_email_any_case_raises_409(db_session):
    service = make_service(db_session)
    await service.register(email="a@x.com", password=PASSWORD, ip=None)
    with pytest.raises(EmailAlreadyRegisteredError) as exc:
        await service.register(email="A@X.COM", password=PASSWORD, ip=None)
    assert exc.value.status_code == 409
    assert "a@x.com" not in exc.value.message.lower()


async def test_session_still_usable_after_duplicate(db_session):
    service = make_service(db_session)
    await service.register(email="a@x.com", password=PASSWORD, ip=None)
    with pytest.raises(EmailAlreadyRegisteredError):
        await service.register(email="a@x.com", password=PASSWORD, ip=None)
    # Fails with "transaction is aborted" if the savepoint was not used.
    users = (await db_session.execute(select(User))).scalars().all()
    assert len(users) == 1


async def test_register_writes_audit_without_secrets(db_session):
    user = await make_service(db_session).register(
        email="a@x.com", password=PASSWORD, ip="203.0.113.10"
    )
    row = (await db_session.execute(select(AuditLog))).scalar_one()
    assert row.action == "auth.register_success"
    assert row.user_id == user.id
    assert row.ip == "203.0.113.10"
    assert PASSWORD not in str(row.meta)