import logging
import os
from typing import Any, ClassVar

import httpx
from arq import func
from arq.connections import RedisSettings
from redis.asyncio import Redis

from app.config import Settings, get_settings
from app.identity.types import VerifiedIdentity
from app.jobs.store import ResultStore
from app.sources.base import SourceError
from app.sources.registry import build_background_sources

logger = logging.getLogger(__name__)


async def run_source_job(
    ctx: dict[str, Any], *, job_id: str, source_name: str, user_id: int, email: str
) -> None:
    store: ResultStore = ctx["store"]
    source = ctx["sources"].get(source_name)
    if source is None:
        await store.fail(job_id, "Fuente desconocida.")
        return
    # Solo se encola desde un endpoint que exige sesión verificada (app/api/analysis.py).
    identity = VerifiedIdentity(user_id=user_id, email=email)
    try:
        findings = await source.collect(identity, None)
    except SourceError as exc:
        await store.fail(job_id, str(exc))
    except Exception:
        # Sin el email en el log: solo la fuente y el job.
        logger.exception("Fallo inesperado en la fuente %s (job %s)", source_name, job_id)
        await store.fail(job_id, "Error inesperado al consultar la fuente. Probá más tarde.")
    else:
        await store.complete(job_id, findings)


def build_job_context(settings: Settings, redis: Redis) -> dict[str, Any]:
    http = httpx.AsyncClient()
    return {
        "redis": redis,
        "http": http,
        "store": ResultStore(redis, settings.result_ttl_seconds),
        "sources": build_background_sources(settings, http_client=http, redis=redis),
    }


async def startup(ctx: dict[str, Any]) -> None:
    ctx.update(build_job_context(get_settings(), ctx["redis"]))


async def shutdown(ctx: dict[str, Any]) -> None:
    await ctx["http"].aclose()


class WorkerSettings:
    functions: ClassVar = [func(run_source_job, keep_result=0, max_tries=1)]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = RedisSettings.from_dsn(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    # Las fuentes ya reintentan con backoff; arq no guarda resultados (van al ResultStore).
    keep_result = 0
    max_jobs = 10
