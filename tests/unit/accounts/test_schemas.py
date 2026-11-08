import pytest
from pydantic import ValidationError

from app.modules.accounts.schemas import RegisterRequest

GOOD = "correct horse battery staple"


def test_email_is_trimmed_and_lowercased():
    req = RegisterRequest(email="  Alice@Example.COM ", password=GOOD)
    assert req.email == "alice@example.com"


@pytest.mark.parametrize(
    "password",
    [
        "short-pw-1",          # < 12
        "a" * 11,
        "            ",        # blank
        "password1234",        # common
        "123456789012",        # common
        "x" * 129,             # > 128 (argon2 DoS guard)
    ],
)
def test_weak_or_oversized_password_rejected(password):
    with pytest.raises(ValidationError):
        RegisterRequest(email="a@example.com", password=password)


def test_long_passphrase_without_composition_rules_is_accepted():
    # NIST 800-63B: length matters, not "must contain a symbol".
    assert RegisterRequest(email="a@example.com", password=GOOD)


def test_invalid_email_rejected():
    with pytest.raises(ValidationError):
        RegisterRequest(email="not-an-email", password=GOOD)


def test_extra_fields_forbidden():
    with pytest.raises(ValidationError):
        RegisterRequest(email="a@example.com", password=GOOD, is_active=True)