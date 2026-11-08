import json

import structlog

from app.core.logging import configure_logging, redact_secrets

FAKE_JWT = (
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuvwxyz0123456789"
)


def test_redacts_sensitive_keys_case_insensitively_and_recursively():
    event = {
        "event": "login",
        "password": "hunter2",
        "Authorization": "Bearer abc",
        "nested": {"refresh_token": "r-token", "ok": 1},
        "items": [{"api_key": "k"}, {"safe": "v"}],
        "user_id": "u1",
    }
    out = redact_secrets(None, "info", event)
    assert out["password"] == "***"
    assert out["Authorization"] == "***"
    assert out["nested"]["refresh_token"] == "***"
    assert out["nested"]["ok"] == 1
    assert out["items"][0]["api_key"] == "***"
    assert out["items"][1]["safe"] == "v"
    assert out["user_id"] == "u1"  # non-sensitive data must survive


def test_redacts_jwt_looking_values_in_free_text():
    out = redact_secrets(None, "info", {"event": f"called with Bearer {FAKE_JWT}"})
    assert FAKE_JWT not in out["event"]


def test_does_not_mutate_input():
    event = {"event": "x", "password": "p"}
    redact_secrets(None, "info", event)
    assert event["password"] == "p"


def test_output_is_one_json_object_per_line(capsys):
    configure_logging()
    structlog.get_logger().info("hello", password="hunter2", user_id="u1")
    captured = capsys.readouterr()
    line = (captured.out + captured.err).strip().splitlines()[-1]
    data = json.loads(line)
    assert data["event"] == "hello"
    assert data["password"] == "***"
    assert "timestamp" in data and "level" in data
    assert "hunter2" not in line