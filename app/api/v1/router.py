from fastapi import APIRouter

from app.api.v1 import health

api_router = APIRouter()
api_router.include_router(health.router)
# Phase 1: include module routers here as they are implemented, e.g.
# api_router.include_router(accounts_router, prefix="/auth", tags=["auth"])
