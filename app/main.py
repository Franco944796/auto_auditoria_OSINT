from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from redis.asyncio import Redis

from app.api.analysis import router as analysis_router
from app.api.photos import router as photos_router
from app.api.report import router as report_router
from app.config import Settings, get_settings
from app.db import init_db, make_engine, make_sessionmaker
from app.identity.mailer import Mailer, build_mailer
from app.identity.routes import router as identity_router
from app.jobs.queue import ArqJobQueue, JobQueue
from app.security.middleware import install_security_middleware, rate_limited_response
from app.security.ratelimit import RateLimitExceeded
from app.web.pages import STATIC_DIR
from app.web.pages import router as pages_router


def create_app(
    settings: Settings | None = None,
    *,
    redis: Redis | None = None,
    mailer: Mailer | None = None,
    job_queue: JobQueue | None = None,
) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = make_engine(settings.database_url)
        await init_db(engine)
        app.state.sessionmaker = make_sessionmaker(engine)
        app.state.redis = redis or Redis.from_url(settings.redis_url)
        app.state.mailer = mailer or build_mailer(settings)
        app.state.job_queue = job_queue or await ArqJobQueue.connect(settings.redis_url)
        try:
            yield
        finally:
            if job_queue is None:
                await app.state.job_queue.close()
            if redis is None:
                await app.state.redis.aclose()
            await engine.dispose()

    app = FastAPI(
        title="Autoauditoría de exposición digital",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.environment == "development" else None,
    )
    app.state.settings = settings

    @app.exception_handler(RateLimitExceeded)
    async def _rate_limited(request: Request, exc: RateLimitExceeded) -> Response:
        return rate_limited_response(exc)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(identity_router)
    app.include_router(analysis_router)
    app.include_router(photos_router)
    app.include_router(report_router)
    app.include_router(pages_router)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    install_security_middleware(app, settings)
    return app
