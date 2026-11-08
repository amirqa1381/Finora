import os

import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from tests.conftest import run_alembic

# A SEPARATE empty database: this test drops everything.
MIGRATION_DB = os.environ.get(
    "MIGRATION_TEST_DATABASE_URL",
    "postgresql+asyncpg://finora:finora@localhost:5432/finora_migration_test",
)
STAGE_AB_TABLES = {"users", "user_settings", "refresh_tokens", "audit_logs"}


async def _tables() -> set[str]:
    eng = create_async_engine(MIGRATION_DB)
    try:
        async with eng.connect() as conn:
            rows = await conn.execute(
                text("select tablename from pg_tables where schemaname='public'")
            )
            return {r[0] for r in rows}
    finally:
        await eng.dispose()


@pytest_asyncio.fixture(autouse=True)
async def _clean():
    run_alembic("downgrade", "base", database_url=MIGRATION_DB)
    yield
    run_alembic("downgrade", "base", database_url=MIGRATION_DB)


async def test_upgrade_head_creates_stage_ab_tables():
    run_alembic("upgrade", "head", database_url=MIGRATION_DB)
    assert STAGE_AB_TABLES <= await _tables()


async def test_downgrade_base_removes_everything_except_alembic_version():
    run_alembic("upgrade", "head", database_url=MIGRATION_DB)
    run_alembic("downgrade", "base", database_url=MIGRATION_DB)
    assert (await _tables()) - {"alembic_version"} == set()


async def test_upgrade_downgrade_upgrade_is_repeatable():
    for _ in range(2):
        run_alembic("upgrade", "head", database_url=MIGRATION_DB)
        run_alembic("downgrade", "base", database_url=MIGRATION_DB)


async def test_email_uniqueness_is_enforced_case_insensitively_in_db():
    run_alembic("upgrade", "head", database_url=MIGRATION_DB)
    eng = create_async_engine(MIGRATION_DB)
    try:
        async with eng.connect() as conn:
            defs = [
                r[0]
                for r in await conn.execute(
                    text("select indexdef from pg_indexes where tablename='users'")
                )
            ]
    finally:
        await eng.dispose()
    assert any("UNIQUE" in d and "lower(" in d for d in defs), defs