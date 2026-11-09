import base64
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt
import pytest

from app.core import security
from app.core.config import get_settings

SETTINGS = get_settings()


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _claims(**over) -> dict:
    now = datetime.now(timezone.utc)
    base = {
        "sub": str(uuid4()),
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=15)).timestamp()),
    }
    return {**base, **over}


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


# ---------- access tokens ----------
def test_access_token_roundtrip_and_ttl():
    uid = uuid4()
    token = security.create_access_token(uid)
    assert security.decode_access_token(token) == uid
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["type"] == "access"
    assert claims["exp"] - claims["iat"] == SETTINGS.access_token_ttl_seconds
    assert SETTINGS.access_token_ttl_seconds <= 15 * 60


def test_expired_token_rejected():
    past = datetime.now(timezone.utc) - timedelta(seconds=SETTINGS.access_token_ttl_seconds + 5)
    token = security.create_access_token(uuid4(), now=past)
    with pytest.raises(security.InvalidTokenError):
        security.decode_access_token(token)


def test_tampered_payload_rejected():
    token = security.create_access_token(uuid4())
    header, _payload, sig = token.split(".")
    forged = f"{header}.{_b64(_claims())}.{sig}"
    with pytest.raises(security.InvalidTokenError):
        security.decode_access_token(forged)


def test_tampered_signature_rejected():
    header, payload, sig = security.create_access_token(uuid4()).split(".")
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
    token = jwt.encode(_claims(type="refresh"), SETTINGS.jwt_secret.get_secret_value(), algorithm="HS256")
    with pytest.raises(security.InvalidTokenError):
        security.decode_access_token(token)


def test_missing_exp_rejected():
    claims = _claims()
    del claims["exp"]
    token = jwt.encode(claims, SETTINGS.jwt_secret.get_secret_value(), algorithm="HS256")
    with pytest.raises(security.InvalidTokenError):
        security.decode_access_token(token)


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