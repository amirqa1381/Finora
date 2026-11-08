from collections import Counter
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.core import security
from app.core.config import get_settings

API = "/api/v1"
PASSWORD = "correct horse battery staple"
SETTINGS = get_settings()


# ------------------------------------------------------------- helpers
async def register(client, email="alice@example.com", password=PASSWORD):
    return await client.post(f"{API}/auth/register", json={"email": email, "password": password})


async def login(client, email="alice@example.com", password=PASSWORD):
    return await client.post(f"{API}/auth/login", json={"email": email, "password": password})


async def refresh(client, token):
    return await client.post(f"{API}/auth/refresh", json={"refresh_token": token})


async def logout(client, token):
    return await client.post(f"{API}/auth/logout", json={"refresh_token": token})


async def signed_in(client, email="alice@example.com") -> dict:
    assert (await register(client, email)).status_code == 201
    r = await login(client, email)
    assert r.status_code == 200
    return r.json()


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------------- register
async def test_register_success(client, db_session):
    r = await register(client, email="Alice@Example.COM")
    assert r.status_code == 201
    body = r.json()
    assert body["email"] == "alice@example.com"
    assert UUID(body["id"])
    assert "password" not in r.text and "password_hash" not in r.text

    row = (
        await db_session.execute(
            text("select email, password_hash from users where id = :i"), {"i": body["id"]}
        )
    ).one()
    assert row.email == "alice@example.com"
    assert row.password_hash.startswith("$argon2id$")
    n = (
        await db_session.execute(
            text("select count(*) from user_settings where user_id = :i"), {"i": body["id"]}
        )
    ).scalar_one()
    assert n == 1  # users 1-1 user_settings


async def test_register_duplicate_email_is_case_insensitive(client):
    assert (await register(client, "alice@example.com")).status_code == 201
    r = await register(client, "ALICE@example.com")
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "email_already_registered"


async def test_register_weak_password_422(client):
    assert (await register(client, password="short")).status_code == 422


async def test_register_rejects_unknown_fields(client):
    r = await client.post(
        f"{API}/auth/register",
        json={"email": "a@example.com", "password": PASSWORD, "is_active": False},
    )
    assert r.status_code == 422


# ------------------------------------------------------------- login
async def test_login_success_shape(client):
    await register(client)
    r = await login(client)
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == SETTINGS.access_token_ttl_seconds
    assert body["access_token"] and body["refresh_token"]


async def test_login_email_is_case_insensitive(client):
    await register(client)
    assert (await login(client, email="ALICE@EXAMPLE.COM")).status_code == 200


async def test_login_failures_are_indistinguishable(client, db_session):
    await register(client, "alice@example.com")
    await register(client, "inactive@example.com")
    await db_session.execute(
        text("update users set is_active=false where email='inactive@example.com'")
    )

    unknown = await login(client, email="nobody@example.com")
    wrong_pw = await login(client, password="totally-wrong-password")
    inactive = await login(client, email="inactive@example.com")

    for r in (unknown, wrong_pw, inactive):
        assert r.status_code == 401
    assert unknown.json() == wrong_pw.json() == inactive.json()
    assert unknown.json()["error"]["message"] == "Email or password is wrong"


async def test_unknown_email_still_burns_a_password_hash_verification(client, monkeypatch):
    """Timing side-channel guard: unknown email must cost the same as a wrong password."""
    calls = []
    real = security.verify_password

    def spy(pw, hashed):
        calls.append(1)
        return real(pw, hashed)

    monkeypatch.setattr("app.modules.accounts.service.verify_password", spy)
    r = await login(client, email="nobody@example.com")
    assert r.status_code == 401
    assert len(calls) == 1


async def test_refresh_token_is_stored_only_as_hash(client, db_session):
    tokens = await signed_in(client)
    hashes = [
        r[0] for r in await db_session.execute(text("select token_hash from refresh_tokens"))
    ]
    assert hashes == [security.hash_refresh_token(tokens["refresh_token"])]
    assert tokens["refresh_token"] not in hashes


# ------------------------------------------------------------- refresh
async def test_refresh_rotates_token(client):
    t1 = await signed_in(client)
    r = await refresh(client, t1["refresh_token"])
    assert r.status_code == 200
    t2 = r.json()
    assert t2["refresh_token"] != t1["refresh_token"]
    assert (await client.get(f"{API}/me", headers=bearer(t2["access_token"]))).status_code == 200


async def test_reuse_of_rotated_token_revokes_all_sessions_of_that_user(client, db_session):
    await register(client)
    device_a = (await login(client)).json()
    device_b = (await login(client)).json()
    a2 = (await refresh(client, device_a["refresh_token"])).json()

    # attacker (or buggy client) replays the already-rotated token
    replay = await refresh(client, device_a["refresh_token"])
    assert replay.status_code == 401

    # every session of this user is now dead
    assert (await refresh(client, a2["refresh_token"])).status_code == 401
    assert (await refresh(client, device_b["refresh_token"])).status_code == 401
    active = (
        await db_session.execute(
            text("select count(*) from refresh_tokens where revoked_at is null")
        )
    ).scalar_one()
    assert active == 0


async def test_refresh_with_expired_token_401(client, db_session):
    t = await signed_in(client)
    await db_session.execute(
        text("update refresh_tokens set expires_at = now() - interval '1 second'")
    )
    assert (await refresh(client, t["refresh_token"])).status_code == 401


async def test_refresh_with_unknown_token_401(client):
    assert (await refresh(client, "definitely-not-a-real-token")).status_code == 401


async def test_access_token_is_not_accepted_as_refresh_token(client):
    t = await signed_in(client)
    assert (await refresh(client, t["access_token"])).status_code == 401


# ------------------------------------------------------------- logout
async def test_logout_revokes_refresh_token(client):
    t = await signed_in(client)
    assert (await logout(client, t["refresh_token"])).status_code == 204
    assert (await refresh(client, t["refresh_token"])).status_code == 401


async def test_logout_is_idempotent_and_not_an_oracle(client):
    assert (await logout(client, "never-existed")).status_code == 204


# ------------------------------------------------------------- /me
async def test_me_requires_token(client):
    r = await client.get(f"{API}/me")
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


async def test_me_returns_profile_without_secrets(client):
    t = await signed_in(client)
    r = await client.get(f"{API}/me", headers=bearer(t["access_token"]))
    assert r.status_code == 200
    assert r.json()["email"] == "alice@example.com"
    assert "password" not in r.text


async def _user_id(client, token) -> UUID:
    return UUID((await client.get(f"{API}/me", headers=bearer(token))).json()["id"])


async def test_me_rejects_expired_token(client):
    t = await signed_in(client)
    uid = await _user_id(client, t["access_token"])
    old = datetime.now(timezone.utc) - timedelta(hours=1)
    expired = security.create_access_token(uid, now=old)
    assert (await client.get(f"{API}/me", headers=bearer(expired))).status_code == 401


async def test_me_rejects_tampered_token(client):
    t = await signed_in(client)
    h, p, s = t["access_token"].split(".")
    bad_sig = s[:5] + ("A" if s[5] != "A" else "B") + s[6:]
    assert (await client.get(f"{API}/me", headers=bearer(f"{h}.{p}.{bad_sig}"))).status_code == 401


async def test_me_rejects_refresh_token_used_as_bearer(client):
    t = await signed_in(client)
    assert (await client.get(f"{API}/me", headers=bearer(t["refresh_token"]))).status_code == 401


async def test_me_rejects_token_of_deactivated_user(client, db_session):
    t = await signed_in(client)
    await db_session.execute(text("update users set is_active=false"))
    assert (await client.get(f"{API}/me", headers=bearer(t["access_token"]))).status_code == 401


async def test_me_rejects_valid_signature_for_nonexistent_user(client):
    ghost = security.create_access_token(uuid4())
    assert (await client.get(f"{API}/me", headers=bearer(ghost))).status_code == 401


# ------------------------------------------------------------- rate limits
async def test_login_lockout_after_max_failures_even_with_correct_password(client):
    await register(client)
    for _ in range(SETTINGS.login_max_failures):
        assert (await login(client, password="wrong-password-123")).status_code == 401
    r = await login(client)  # correct password, but locked
    assert r.status_code == 429
    assert int(r.headers["retry-after"]) > 0
    assert r.json()["error"]["code"] == "rate_limited"


async def test_lockout_is_scoped_to_ip_and_email(client, client_factory):
    await register(client, "alice@example.com")
    await register(client, "bob@example.com")
    for _ in range(SETTINGS.login_max_failures):
        await login(client, password="wrong-password-123")
    assert (await login(client)).status_code == 429
    assert (await login(client, email="bob@example.com")).status_code == 200  # other email
    other_ip = client_factory(ip="198.51.100.7")
    assert (await login(other_ip)).status_code == 200  # attacker can't lock the victim out elsewhere


async def test_successful_login_resets_failure_counter(client):
    await register(client)
    n = SETTINGS.login_max_failures
    for _ in range(n - 1):
        await login(client, password="wrong-password-123")
    assert (await login(client)).status_code == 200
    for _ in range(n - 1):
        assert (await login(client, password="wrong-password-123")).status_code == 401


async def test_spoofed_x_forwarded_for_does_not_bypass_lockout(client):
    await register(client)
    for i in range(SETTINGS.login_max_failures):
        r = await client.post(
            f"{API}/auth/login",
            json={"email": "alice@example.com", "password": "wrong-password-123"},
            headers={"X-Forwarded-For": f"10.0.0.{i}"},
        )
        assert r.status_code == 401
    r = await client.post(
        f"{API}/auth/login",
        json={"email": "alice@example.com", "password": PASSWORD},
        headers={"X-Forwarded-For": "10.9.9.9"},
    )
    assert r.status_code == 429


async def test_register_is_rate_limited_per_ip(client):
    for i in range(SETTINGS.register_max_per_window):
        assert (await register(client, f"user{i}@example.com")).status_code == 201
    r = await register(client, "one-too-many@example.com")
    assert r.status_code == 429
    assert "retry-after" in r.headers


# ------------------------------------------------------------- audit log
async def _audit(db_session):
    rows = await db_session.execute(
        text("select action, user_id, ip, metadata::text as meta from audit_logs")
    )
    return rows.all()


async def test_audit_records_auth_events_without_secrets(client, db_session):
    t = await signed_in(client)
    await login(client, email="ghost@example.com", password="wrong-password-xyz")
    await logout(client, t["refresh_token"])

    rows = await _audit(db_session)
    actions = Counter(r.action for r in rows)
    assert actions["auth.register"] == 1
    assert actions["auth.login.success"] == 1
    assert actions["auth.login.failure"] == 1  # must survive the 401 (not rolled back!)
    assert actions["auth.logout"] == 1

    failure = next(r for r in rows if r.action == "auth.login.failure")
    assert failure.user_id is None  # unknown email
    assert all("203.0.113.10" in r.ip for r in rows)

    blob = " ".join(r.meta for r in rows)
    for secret in (PASSWORD, "wrong-password-xyz", t["access_token"], t["refresh_token"]):
        assert secret not in blob


async def test_audit_records_refresh_reuse_detection(client, db_session):
    t = await signed_in(client)
    await refresh(client, t["refresh_token"])
    await refresh(client, t["refresh_token"])  # replay
    actions = {r.action for r in await _audit(db_session)}
    assert "auth.refresh.reuse_detected" in actions


async def test_audit_log_is_append_only_at_database_level(client, db_session):
    await signed_in(client)
    with pytest.raises(DBAPIError):
        async with db_session.begin_nested():
            await db_session.execute(text("update audit_logs set action = 'tampered'"))
    with pytest.raises(DBAPIError):
        async with db_session.begin_nested():
            await db_session.execute(text("delete from audit_logs"))


# ------------------------------------------------------------- logging
async def test_logs_never_contain_passwords_or_tokens(client, capsys):
    from app.core.logging import configure_logging

    configure_logging()  # re-bind to the captured stdout
    t = await signed_in(client)
    await login(client, password="wrong-password-xyz")
    t2 = (await refresh(client, t["refresh_token"])).json()
    await logout(client, t2["refresh_token"])

    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert output.strip(), "auth flow must log something, otherwise this test proves nothing"
    for secret in (
        PASSWORD,
        "wrong-password-xyz",
        t["access_token"],
        t["refresh_token"],
        t2["access_token"],
        t2["refresh_token"],
    ):
        assert secret not in output