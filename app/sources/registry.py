from typing import Any

import httpx
from redis.asyncio import Redis

from app.config import Settings
from app.sources.base import Source
from app.sources.exif import ExifSource
from app.sources.hibp import HibpSource
from app.sources.pacing import RedisPacer
from app.sources.pwned_passwords import PwnedPasswordsSource

# Para agregar una fuente: crear su módulo en sources/ y sumarla acá (y a la factoría si corre
# en segundo plano). El resto de la app la descubre por nombre.
SOURCE_CLASSES: tuple[type[Source[Any]], ...] = (HibpSource, PwnedPasswordsSource, ExifSource)

BACKGROUND_SOURCES = frozenset(cls.name for cls in SOURCE_CLASSES if cls.runs_in_background)


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
    return {hibp.name: hibp}
