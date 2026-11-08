from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import AsyncIterator, Callable
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine

ROOT = Path(__file__).resolve().parents[1]
TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL", "postgresql+asyncpg://finora:finora@localhost:5432/finora_test"
)
TEST_REDIS_URL = os.environ.get("TEST_REDIS_URL", "redis://localhost:6379/15")

# Must be set BEFORE the app (and its cached settings) is imported.
os.environ["DATABASE_URL"] = TEST_DATABASE_URL
os.environ["REDIS_URL"] = TEST_REDIS_URL
os.environ.setdefault("JWT_SECRET", "test-only-secret-" + "x" * 48)


def run_alembic(*args: str, database_url: str) -> None:
    subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=ROOT,
        env={**os.environ, "DATABASE_URL": database_url},
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.fixture(scope="session")
def migrated_db() -> None:
    """The test DB is built by the REAL migrations, never by create_all()."""
    run_alembic("upgrade", "head", database_url=TEST_DATABASE_URL)


@pytest_asyncio.fixture(scope="session")
async def engine(migrated_db: None) -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(TEST_DATABASE_URL)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def db_session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """Every test runs inside an outer transaction that is rolled back.
    session.commit() inside the app only releases a SAVEPOINT."""
    async with engine.connect() as conn:
        outer = await conn.begin()
        session = AsyncSession(
            bind=conn, join_transaction_mode="create_savepoint", expire_on_commit=False
        )
        try:
            yield session
        finally:
            await session.close()
            await outer.rollback()


@pytest_asyncio.fixture
async def redis() -> AsyncIterator[Redis]:
    r = Redis.from_url(TEST_REDIS_URL, decode_responses=True)
    await r.flushdb()
    yield r
    await r.flushdb()
    await r.aclose()


@pytest_asyncio.fixture
async def app(db_session: AsyncSession, redis: Redis):
    from app.api import deps
    from app.main import create_app

    application = create_app()

    async def _db() -> AsyncIterator[AsyncSession]:
        yield db_session

    async def _redis() -> Redis:
        return redis

    application.dependency_overrides[deps.get_db_session] = _db
    application.dependency_overrides[deps.get_redis] = _redis
    return application


@pytest_asyncio.fixture
async def client_factory(app) -> AsyncIterator[Callable[..., AsyncClient]]:
    created: list[AsyncClient] = []

    def make(ip: str = "203.0.113.10", raise_app_exceptions: bool = True) -> AsyncClient:
        transport = ASGITransport(
            app=app, raise_app_exceptions=raise_app_exceptions, client=(ip, 50000)
        )
        c = AsyncClient(transport=transport, base_url="http://test")
        created.append(c)
        return c

    yield make
    for c in created:
        await c.aclose()


@pytest_asyncio.fixture
async def client(client_factory: Callable[..., AsyncClient]) -> AsyncClient:
    return client_factory()