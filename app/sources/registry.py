from typing import Any

import httpx
from redis.asyncio import Redis

from app.config import Settings
from app.security.ratelimit import RateLimiter
from app.sources.base import Source
from app.sources.exif import ExifSource
from app.sources.hibp import HibpSource
from app.sources.pacing import RedisPacer
from app.sources.pwned_passwords import PwnedPasswordsSource
from app.sources.xposedornot import XposedOrNotSource

# Para agregar una fuente: crear su módulo en sources/ y sumarla acá (y a la factoría si corre
# en segundo plano). El resto de la app la descubre por nombre.
SOURCE_CLASSES: tuple[type[Source[Any]], ...] = (
    HibpSource,
    XposedOrNotSource,
    PwnedPasswordsSource,
    ExifSource,
)
SOURCES_BY_NAME = {cls.name: cls for cls in SOURCE_CLASSES}


def enabled_breach_source(settings: Settings) -> type[Source[Any]]:
    choice = settings.breach_source
    if choice == "auto":
        choice = "hibp" if settings.hibp_api_key.get_secret_value() else "xposedornot"
    return SOURCES_BY_NAME[choice]


def enabled_background_sources(settings: Settings) -> frozenset[str]:
    return frozenset({enabled_breach_source(settings).name})


def build_background_sources(
    settings: Settings, *, http_client: httpx.AsyncClient, redis: Redis
) -> dict[str, Source[None]]:
    hibp = HibpSource(
        api_key=settings.hibp_api_key.get_secret_value(),
        user_agent=settings.hibp_user_agent,
        client=http_client,
        pacer=RedisPacer(redis, "pace:hibp", 60 / settings.hibp_requests_per_minute),
        max_retries=settings.hibp_max_retries,
    )
    xposedornot = XposedOrNotSource(
        client=http_client,
        user_agent=settings.hibp_user_agent,
        pacer=RedisPacer(redis, "pace:xposedornot", 0.5),
        quota=RateLimiter(redis),
    )
    return {hibp.name: hibp, xposedornot.name: xposedornot}
