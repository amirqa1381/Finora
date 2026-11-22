import base64
import json
from datetime import datetime, timedelta, UTC
from uuid import uuid4

import jwt
import pytest

from app.core import security
from app.core.config import get_settings

SETTINGS = get_settings()


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _claims(**over) -> dict:
    """A valid access-token payload. Tests override one field to break it."""
    now = datetime.now(UTC)
    base = {
        "sub": str(uuid4()),
        "sid": str(uuid4()),  # session id: a required claim
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=15)).timestamp()),
    }
    return {**base, **over}


def _sign(claims: dict) -> str:
    return jwt.encode(claims, SETTINGS.jwt_secret.get_secret_value(), algorithm="HS256")


# ---------- passwords ----------
def test_hash_is_argon2id_and_never_contains_plaintext():
    h = security.hash_password("correct horse battery staple")
    assert h.startswith("$argon2id$")
    assert "correct horse" not in h


def test_hashes_are_salted():
    assert security.hash_password("same-password-123") != security.hash_password("same-password-123")


def test_verify_password_true_and_false():
    h = security.hash_password("correct horse battery staple")
    assert security.verify_password("correct horse battery staple", h) is True
    assert security.verify_password("wrong horse battery staple", h) is False


@pytest.mark.parametrize("garbage", ["", "not-a-hash", "$argon2id$broken", "x" * 500])
def test_verify_password_never_raises_on_garbage_hash(garbage):
    assert security.verify_password("whatever-password", garbage) is False


def test_dummy_hash_is_valid_and_stable():
    first = security.get_dummy_password_hash()
    assert first.startswith("$argon2id$")
    assert security.get_dummy_password_hash() == first  # built once
    assert security.verify_password("any-password-123", first) is False


# ---------- access tokens ----------
def test_access_token_roundtrip_and_ttl():
    uid, sid = uuid4(), uuid4()
    token = security.create_access_token(uid, session_id=sid)
    decoded = security.decode_access_token(token)
    assert decoded.user_id == uid
    assert decoded.session_id == sid
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["type"] == "access"
    assert claims["sid"] == str(sid)
    assert claims["exp"] - claims["iat"] == SETTINGS.access_token_ttl_seconds
    assert SETTINGS.access_token_ttl_seconds <= 15 * 60


def test_expired_token_rejected():
    past = datetime.now(UTC) - timedelta(seconds=SETTINGS.access_token_ttl_seconds + 5)
    token = security.create_access_token(uuid4(), session_id=uuid4(), now=past)
    with pytest.raises(security.InvalidTokenError):
        security.decode_access_token(token)


def test_tampered_payload_rejected():
    token = security.create_access_token(uuid4(), session_id=uuid4())
    header, _payload, sig = token.split(".")
    forged = f"{header}.{_b64(_claims())}.{sig}"
    with pytest.raises(security.InvalidTokenError):
        security.decode_access_token(forged)


def test_tampered_signature_rejected():
    header, payload, sig = security.create_access_token(uuid4(), session_id=uuid4()).split(".")
    bad_sig = sig[:5] + ("A" if sig[5] != "A" else "B") + sig[6:]
    with pytest.raises(security.InvalidTokenError):
        security.decode_access_token(f"{header}.{payload}.{bad_sig}")


def test_alg_none_rejected():
    token = jwt.encode(_claims(), key=None, algorithm="none")
    with pytest.raises(security.InvalidTokenError):
        security.decode_access_token(token)


def test_wrong_secret_rejected():
    token = jwt.encode(_claims(), "another-secret-" + "y" * 48, algorithm="HS256")
    with pytest.raises(security.InvalidTokenError):
        security.decode_access_token(token)


def test_wrong_token_type_rejected():
    with pytest.raises(security.InvalidTokenError, match="wrong token type"):
        security.decode_access_token(_sign(_claims(type="refresh")))


def test_missing_exp_rejected():
    claims = _claims()
    del claims["exp"]
    with pytest.raises(security.InvalidTokenError):
        security.decode_access_token(_sign(claims))


def test_missing_sid_rejected():
    claims = _claims()
    del claims["sid"]
    with pytest.raises(security.InvalidTokenError):
        security.decode_access_token(_sign(claims))


@pytest.mark.parametrize("bad_sid", ["not-a-uuid", "", 12345, None, ["a"]])
def test_invalid_sid_rejected(bad_sid):
    with pytest.raises(security.InvalidTokenError):
        security.decode_access_token(_sign(_claims(sid=bad_sid)))


@pytest.mark.parametrize("bad_sub", ["not-a-uuid", "", 12345, None])
def test_invalid_sub_rejected(bad_sub):
    with pytest.raises(security.InvalidTokenError):
        security.decode_access_token(_sign(_claims(sub=bad_sub)))


def test_signature_protects_sid_from_edits():
    """Changing sid in the payload without re-signing must fail."""
    token = security.create_access_token(uuid4(), session_id=uuid4())
    header, payload, sig = token.split(".")
    padded = payload + "=" * (-len(payload) % 4)
    data = json.loads(base64.urlsafe_b64decode(padded))
    data["sid"] = str(uuid4())
    forged = f"{header}.{_b64(data)}.{sig}"
    with pytest.raises(security.InvalidTokenError):
        security.decode_access_token(forged)


@pytest.mark.parametrize("junk", ["", "abc", "a.b.c", "....", "Bearer x"])
def test_garbage_token_rejected(junk):
    with pytest.raises(security.InvalidTokenError):
        security.decode_access_token(junk)


# ---------- refresh tokens ----------
def test_refresh_token_generation():
    raw, hashed = security.generate_refresh_token()
    raw2, hashed2 = security.generate_refresh_token()
    assert raw != raw2 and hashed != hashed2
    assert len(raw) >= 43  # >= 256 bits of entropy, urlsafe-encoded
    assert raw != hashed and raw not in hashed
    assert security.hash_refresh_token(raw) == hashed  # deterministic -> DB lookup works
    assert len(hashed) == 64  # sha256 hex