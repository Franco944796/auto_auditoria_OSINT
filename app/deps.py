from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.identity.mailer import Mailer
from app.identity.service import VerificationService
from app.identity.types import VerifiedIdentity
from app.security.ratelimit import Limit, RateLimiter, subject_key

SESSION_COOKIE = "session"


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


async def get_db(request: Request) -> AsyncIterator[AsyncSession]:
    async with request.app.state.sessionmaker() as session:
        yield session


def get_redis(request: Request) -> Redis:
    return request.app.state.redis


def get_mailer(request: Request) -> Mailer:
    return request.app.state.mailer


def get_limiter(request: Request) -> RateLimiter:
    return RateLimiter(request.app.state.redis)


def client_ip(request: Request) -> str:
    # Detrás de Caddy, uvicorn --proxy-headers ya reemplaza client.host por la IP real.
    return request.client.host if request.client else "desconocida"


def get_verification(
    db: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> VerificationService:
    return VerificationService(db, settings)


async def current_identity(
    request: Request,
    service: Annotated[VerificationService, Depends(get_verification)],
) -> VerifiedIdentity:
    raw = request.cookies.get(SESSION_COOKIE)
    identity = await service.resolve_session(raw) if raw else None
    if identity is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Necesitás verificar tu email para continuar."
        )
    return identity


def limit_ip(scope: str, limit: Limit) -> Callable[..., Awaitable[None]]:
    async def dependency(
        request: Request, limiter: Annotated[RateLimiter, Depends(get_limiter)]
    ) -> None:
        await limiter.hit(f"{scope}:ip:{subject_key(client_ip(request))}", limit)

    return dependency


def limit_account(scope: str, limit: Limit) -> Callable[..., Awaitable[VerifiedIdentity]]:
    async def dependency(
        identity: Annotated[VerifiedIdentity, Depends(current_identity)],
        limiter: Annotated[RateLimiter, Depends(get_limiter)],
    ) -> VerifiedIdentity:
        await limiter.hit(f"{scope}:user:{identity.user_id}", limit)
        return identity

    return dependency


SettingsDep = Annotated[Settings, Depends(get_settings)]
VerificationDep = Annotated[VerificationService, Depends(get_verification)]
IdentityDep = Annotated[VerifiedIdentity, Depends(current_identity)]
LimiterDep = Annotated[RateLimiter, Depends(get_limiter)]
MailerDep = Annotated[Mailer, Depends(get_mailer)]
RedisDep = Annotated[Redis, Depends(get_redis)]
