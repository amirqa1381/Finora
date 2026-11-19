from uuid import uuid4

from sqlalchemy import select

from app.modules.audit.models import AuditLog
from app.modules.audit.service import AuditService


async def test_record_persists_row(db_session):
    uid = uuid4()
    await AuditService(db_session).record(
        "auth.login_success", user_id=uid, ip="203.0.113.10", meta={"k": "v"}
    )
    row = (await db_session.execute(select(AuditLog))).scalar_one()
    assert row.action == "auth.login_success"
    assert row.user_id == uid
    assert row.meta == {"k": "v"}
    assert row.created_at is not None


async def test_record_defaults_meta_to_empty_dict(db_session):
    await AuditService(db_session).record("auth.logout")
    row = (await db_session.execute(select(AuditLog))).scalar_one()
    assert row.meta == {}
    assert row.user_id is None


async def test_record_and_commit_persists_row(db_session):
    await AuditService(db_session).record_and_commit("auth.login_failure", ip="203.0.113.10")
    row = (await db_session.execute(select(AuditLog))).scalar_one()
    assert row.action == "auth.login_failure"