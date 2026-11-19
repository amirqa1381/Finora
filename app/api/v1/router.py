from fastapi import APIRouter

from app.api.v1 import health
from app.modules.accounts.router import router as accounts_router

api_router = APIRouter()
api_router.include_router(health.router)



api_router.include_router(accounts_router)
