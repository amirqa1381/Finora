import re
import uuid
from collections.abc import Awaitable, Callable

import structlog
from fastapi import FastAPI, Request, Response

REQUEST_ID_HEADER = "X-Request-ID"
_VALID_REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{8,64}")


def _get_or_create_request_id(request: Request) -> str:
    incoming = request.headers.get(REQUEST_ID_HEADER)
    if incoming and _VALID_REQUEST_ID.fullmatch(incoming):
        return incoming
    return str(uuid.uuid4())


async def request_id_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    request_id = _get_or_create_request_id(request)
    request.state.request_id = request_id

    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(request_id=request_id)
    try:
        response = await call_next(request)
    finally:
        structlog.contextvars.clear_contextvars()

    response.headers[REQUEST_ID_HEADER] = request_id
    return response


def register_middleware(app: FastAPI) -> None:
    app.middleware("http")(request_id_middleware)