SECRET_PW = "my-very-secret-passphrase-1"


async def test_unknown_route_uses_standard_error_shape(client):
    r = await client.get("/api/v1/does-not-exist")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "not_found"
    assert "x-request-id" in r.headers


async def test_validation_error_shape_and_never_echoes_input(client):
    r = await client.post(
        "/api/v1/auth/register", json={"email": "not-an-email", "password": SECRET_PW}
    )
    assert r.status_code == 422
    body = r.json()
    assert body["error"]["code"] == "validation_error"
    assert isinstance(body["error"]["details"], list)
    assert body["error"]["details"][0].keys() >= {"field", "message"}
    # FastAPI's default 422 echoes "input"; ours must not.
    assert SECRET_PW not in r.text


async def test_unhandled_exception_is_500_without_internals(app, client_factory):
    @app.get("/__boom")
    async def boom():
        raise RuntimeError("super secret internal detail")

    client = client_factory(raise_app_exceptions=False)
    r = await client.get("/__boom")
    assert r.status_code == 500
    assert r.json()["error"]["code"] == "internal_error"
    assert "super secret" not in r.text
    assert "Traceback" not in r.text


async def test_request_id_echoed_when_valid_and_replaced_when_hostile(client):
    ok = await client.get("/api/v1/health/live", headers={"X-Request-ID": "abc-123"})
    assert ok.headers["x-request-id"] == "abc-123"
    bad = await client.get("/api/v1/health/live", headers={"X-Request-ID": "x" * 500})
    assert bad.headers["x-request-id"] != "x" * 500