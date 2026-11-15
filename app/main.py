from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from redis.asyncio import Redis

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging
from app.core.middleware import register_middleware
from app.db.session import get_engine


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    app.state.redis = Redis.from_url(get_settings().redis_url, decode_responses=True)
    try:
        yield
    finally:
        await app.state.redis.aclose()
        await get_engine().dispose()


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        docs_url="/docs",
        lifespan=lifespan,
    )
    app.include_router(api_router, prefix="/api/v1")
    register_middleware(app)
    register_exception_handlers(app)
    return app


app = create_app()