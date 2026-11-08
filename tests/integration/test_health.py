import asyncio
import time

from app.api import deps


class BrokenRedis:
    async def ping(self):
        raise ConnectionError("redis refused password=hunter2")


class SlowRedis:
    async def ping(self):
        await asyncio.sleep(30)


class BrokenSession:
    async def execute(self, *a, **k):
        raise ConnectionError("db down dsn=postgresql://user:secret@db")


async def test_live_is_always_ok(client):
    r = await client.get("/api/v1/health/live")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


async def test_ready_ok_checks_db_and_redis(client):
    r = await client.get("/api/v1/health/ready")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "checks": {"database": "ok", "redis": "ok"}}


async def test_ready_503_when_redis_down_and_no_leak(client, app):
    app.dependency_overrides[deps.get_redis] = lambda: BrokenRedis()
    r = await client.get("/api/v1/health/ready")
    assert r.status_code == 503
    assert r.json()["checks"] == {"database": "ok", "redis": "error"}
    assert "hunter2" not in r.text


async def test_ready_503_when_db_down_and_no_leak(client, app):
    async def bad_db():
        yield BrokenSession()

    app.dependency_overrides[deps.get_db_session] = bad_db
    r = await client.get("/api/v1/health/ready")
    assert r.status_code == 503
    assert r.json()["checks"]["database"] == "error"
    assert "secret" not in r.text


async def test_ready_has_timeout_instead_of_hanging(client, app):
    app.dependency_overrides[deps.get_redis] = lambda: SlowRedis()
    started = time.monotonic()
    r = await client.get("/api/v1/health/ready")
    assert r.status_code == 503
    assert time.monotonic() - started < 5