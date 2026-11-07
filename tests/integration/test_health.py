import pytest


@pytest.mark.anyio
async def test_live(client):
    r = await client.get("/api/v1/health/live")
    assert r.status_code == 200
