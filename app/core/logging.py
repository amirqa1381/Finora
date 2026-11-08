"""Structured JSON logging with automatic secret redaction.

Every log line, whether it comes from our own code (structlog) or from a
library such as uvicorn or SQLAlchemy (stdlib logging), passes through the
same processor chain, so `redact_secrets` cannot be bypassed by accident.
"""
from __future__ import annotations

import json
import logging
import re
import sys
from typing import Any

import structlog

REDACTED = "***"

# A key is sensitive if its lowercase form CONTAINS any of these fragments.
# Substring matching is deliberately conservative: "refresh_token",
# "x-api-key" and "Authorization" are all caught. A false positive (for
# example "token_count") costs a masked value; a false negative leaks a secret.
_SENSITIVE_KEY_FRAGMENTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "api_key",
    "apikey",
    "api-key",
    "cookie",
    "private_key",
    "credential",
)

# Defence in depth: secrets that end up inside free text, not under a key.
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_BEARER_RE = re.compile(r"(?i)\bbearer\s+\S+")

_MAX_DEPTH = 8  # guards against deeply nested or self-referencing structures


def _is_sensitive_key(key: object) -> bool:
    lowered = str(key).lower()
    return any(fragment in lowered for fragment in _SENSITIVE_KEY_FRAGMENTS)


def _scrub_string(value: str) -> str:
    value = _JWT_RE.sub(REDACTED, value)
    return _BEARER_RE.sub(f"Bearer {REDACTED}", value)


def _redact(value: Any, depth: int) -> Any:
    if depth > _MAX_DEPTH:
        return REDACTED
    if isinstance(value, dict):
        return {
            k: REDACTED if _is_sensitive_key(k) else _redact(v, depth + 1)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact(v, depth + 1) for v in value]
    if isinstance(value, str):
        return _scrub_string(value)
    return value


def redact_secrets(_logger: Any, _method_name: str, event_dict: dict) -> dict:
    """structlog processor. Returns a NEW dict; the input is never mutated."""
    return _redact(event_dict, 0)


def _json_dumps(obj: Any, **kwargs: Any) -> str:
    # UUID, Decimal, datetime ... must never crash the logger.
    kwargs["default"] = str
    return json.dumps(obj, **kwargs)


def configure_logging(level: str = "INFO") -> None:
    """Call once at startup (create_app). Safe to call again (tests do)."""
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,  # e.g. request_id bound per request
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso", utc=True, key="timestamp"),
        structlog.processors.format_exc_info,  # traceback -> string, THEN redact
        redact_secrets,  # keep last, so nothing added later can bypass it
    ]

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        # False so a re-configure (tests with capsys) takes effect immediately.
        cache_logger_on_first_use=False,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,  # applies to uvicorn, SQLAlchemy, ...
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(serializer=_json_dumps),
        ],
    )

    # sys.stdout is looked up NOW so that pytest's capsys sees the output.
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    handler._finora = True  # type: ignore[attr-defined]  # marks "ours"

    root = logging.getLogger()
    # Remove only our own previous handler, never pytest's or anyone else's.
    root.handlers = [h for h in root.handlers if not getattr(h, "_finora", False)]
    root.addHandler(handler)
    root.setLevel(level.upper())

    # Route library loggers through the root handler (and so through redaction).
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lib_logger = logging.getLogger(name)
        lib_logger.handlers.clear()
        lib_logger.propagate = True
    # SQLAlchemy at INFO prints every statement with bound parameters.
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
