"""HTTP layer for accounts: thin. Rules live in the service."""

import hashlib
from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.deps import (
    get_accounts_service,
    get_client_ip,
    get_current_user,
    get_rate_limiter,
)
from app.core.config import get_settings
from app.core.exceptions import RateLimitedError
from app.core.rate_limit import RateLimiter
from app.modules.accounts.exceptions import InvalidCredentialsError
from app.modules.accounts.models import User
from app.modules.accounts.schemas import (
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserRead,
)
from app.modules.accounts.service import AccountsService, TokenPair

router = APIRouter(tags=["auth"], prefix="/auth")

Service = Annotated[AccountsService, Depends(get_accounts_service)]
Limiter = Annotated[RateLimiter, Depends(get_rate_limiter)]
ClientIp = Annotated[str | None, Depends(get_client_ip)]


def _token_response(pair: TokenPair) -> TokenResponse:
    return TokenResponse(
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        expires_in=get_settings().access_token_ttl_seconds,
    )


def _login_key(ip: str | None, email: str) -> str:
    # The email is hashed so raw emails never sit in Redis.
    digest = hashlib.sha256(email.strip().lower().encode()).hexdigest()
    return f"rl:login:{ip or 'unknown'}:{digest}"


@router.post("/register", status_code=201, response_model=UserRead)
async def register(
    body: RegisterRequest, service: Service, limiter: Limiter, ip: ClientIp
) -> User:
    settings = get_settings()
    key = f"rl:register:{ip or 'unknown'}"
    count = await limiter.hit(key, window_seconds=settings.register_window_seconds)
    if count > settings.register_max_per_window:
        raise RateLimitedError(
            await limiter.retry_after(key, default=settings.register_window_seconds)
        )
    return await service.register(
        email=body.email, password=body.password.get_secret_value(), ip=ip
    )


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest, service: Service, limiter: Limiter, ip: ClientIp
) -> TokenResponse:
    settings = get_settings()
    key = _login_key(ip, body.email)

    # Locked out: refuse even a correct password.
    if await limiter.count(key) >= settings.login_max_failures:
        raise RateLimitedError(
            await limiter.retry_after(key, default=settings.login_window_seconds)
        )

    try:
        pair = await service.login(
            email=body.email, password=body.password.get_secret_value(), ip=ip
        )
    except InvalidCredentialsError:
        await limiter.hit(key, window_seconds=settings.login_window_seconds)
        raise

    await limiter.reset(key)
    return _token_response(pair)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(body: RefreshRequest, service: Service, ip: ClientIp) -> TokenResponse:
    pair = await service.refresh(
        refresh_token=body.refresh_token.get_secret_value(), ip=ip
    )
    return _token_response(pair)


@router.post("/logout", status_code=204)
async def logout(body: RefreshRequest, service: Service, ip: ClientIp) -> None:
    await service.logout(refresh_token=body.refresh_token.get_secret_value(), ip=ip)


@router.get("/me", response_model=UserRead)
async def me(user: Annotated[User, Depends(get_current_user)]) -> User:
    return user