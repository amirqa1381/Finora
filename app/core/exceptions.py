"""Base application errors and their mapping to HTTP responses."""

from http import HTTPStatus
from typing import ClassVar, cast
from uuid import UUID

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.middleware import REQUEST_ID_HEADER

logger = structlog.get_logger(__name__)


# ============== Exception classes ===============


class AppError(Exception):
    """Base class for all expected (business) errors."""

    status_code: ClassVar[int] = 400
    code: ClassVar[str] = "app_error"
    default_message: ClassVar[str] = "An error occurred"
    headers: ClassVar[dict[str, str] | None] = None

    def __init__(self, message: str | None = None) -> None:
        self.message = message or self.default_message
        super().__init__(self.message)


class NotFoundError(AppError):
    status_code = 404
    code = "not_found"
    default_message = "Resource not found"


class DomainValidationError(AppError):
    # Named "Domain..." to avoid confusion with pydantic.ValidationError.
    status_code = 422
    code = "validation_error"
    default_message = "Validation failed"


class AuthenticationError(AppError):
    status_code = 401
    code = "authentication_error"
    default_message = "Authentication failed"
    headers = {"WWW-Authenticate": "Bearer"}


class AuthorizationError(AppError):
    status_code = 403
    code = "authorization_error"
    default_message = "Not allowed"


# --- Specific (leaf) exceptions ---


class InvalidFieldError(DomainValidationError):
    code = "invalid_field"

    def __init__(self, field: str, reason: str) -> None:
        # Never put the user's input VALUE in `reason`: it ends up in the response.
        self.field = field
        self.reason = reason
        super().__init__(f"Field '{field}' is invalid: {reason}")


class TokenExpiredError(AuthenticationError):
    code = "token_expired"
    default_message = "Token has expired"


class UserNotFoundError(NotFoundError):
    code = "user_not_found"
    default_message = "User not found"

    def __init__(self, user_id: UUID) -> None:
        # The id stays on the object (for logs) but not in the message, so
        # "does not exist" and "belongs to someone else" look identical.
        self.user_id = user_id
        super().__init__()


# ============== Response helpers ===============


def _error_response(
    request: Request,
    status_code: int,
    code: str,
    message: str,
    *,
    details: list[dict[str, str]] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    # getattr: the middleware may not have run (e.g. error inside it).
    request_id = getattr(request.state, "request_id", None)

    error: dict[str, object] = {
        "code": code,
        "message": message,
        "request_id": request_id,
    }
    if details is not None:
        error["details"] = details

    response_headers = dict(headers) if headers else {}
    # 500 responses bypass our middleware, so we set the header here for all.
    if request_id:
        response_headers[REQUEST_ID_HEADER] = request_id

    return JSONResponse(
        status_code=status_code,
        content={"error": error},
        headers=response_headers,
    )


def _field_from_loc(loc: tuple[int | str, ...]) -> str:
    """('body', 'address', 'city') -> 'address.city'; ('query', 'page') -> 'query.page'."""
    parts = [str(p) for p in loc]
    if parts and parts[0] == "body":
        parts = parts[1:]
    return ".".join(parts) or "body"


def _safe_validation_details(exc: RequestValidationError) -> list[dict[str, str]]:
    # Allow-list: only "field" and "message" leave the server.
    # "input" (the user's value, e.g. a password), "ctx" and "url" never do.
    return [
        {"field": _field_from_loc(tuple(err["loc"])), "message": str(err["msg"])}
        for err in exc.errors()
    ]


_HTTP_ERROR_CODES: dict[int, str] = {
    404: "not_found",
    405: "method_not_allowed",
}


# ============== Handlers for FastAPI ===============
# Starlette types handlers as (Request, Exception), so each one takes
# `Exception` and narrows it with cast(); mypy strict rejects narrower params.


async def app_error_handler(request: Request, exc: Exception) -> JSONResponse:
    err = cast(AppError, exc)
    return _error_response(
        request, err.status_code, err.code, err.message, headers=err.headers
    )


async def validation_error_handler(request: Request, exc: Exception) -> JSONResponse:
    err = cast(RequestValidationError, exc)
    return _error_response(
        request,
        422,
        "validation_error",
        "Request validation failed",
        details=_safe_validation_details(err),
    )


async def http_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    err = cast(StarletteHTTPException, exc)
    try:
        message = HTTPStatus(err.status_code).phrase
    except ValueError:
        message = "HTTP error"
    code = _HTTP_ERROR_CODES.get(err.status_code, "http_error")
    # Keep headers Starlette sets itself (e.g. "Allow" on 405).
    return _error_response(
        request, err.status_code, code, message, headers=dict(err.headers or {})
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    # Log the real error (redaction applies), return nothing internal.
    # request_id is passed explicitly: the middleware already cleared contextvars.
    logger.exception(
        "unhandled_exception",
        request_id=getattr(request.state, "request_id", None),
        method=request.method,
        path=request.url.path,
    )
    return _error_response(request, 500, "internal_error", "Internal server error")


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, app_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)