import asyncio
from typing import Any, Protocol, Self

from arq import create_pool
from arq.connections import ArqRedis, RedisSettings

from app.identity.types import VerifiedIdentity


class JobQueue(Protocol):
    async def enqueue(self, job_id: str, source_name: str, identity: VerifiedIdentity) -> None: ...

    async def close(self) -> None: ...


class InProcessJobQueue:
    """Ejecuta los jobs como tareas asyncio de la propia app: sin worker aparte ni polling a
    Redis. Sirve para una sola instancia; con varias réplicas usar ArqJobQueue."""

    def __init__(self, ctx: dict[str, Any]) -> None:
        self.ctx = ctx
        self._tasks: set[asyncio.Task[None]] = set()

    async def enqueue(self, job_id: str, source_name: str, identity: VerifiedIdentity) -> None:
        from app.jobs.worker import run_source_job

        task = asyncio.create_task(
            run_source_job(
                self.ctx,
                job_id=job_id,
                source_name=source_name,
                user_id=identity.user_id,
                email=identity.email,
            )
        )
        # Sin una referencia fuerte, asyncio puede recolectar la tarea antes de que termine.
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def close(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self.ctx["http"].aclose()


class ArqJobQueue:
    def __init__(self, pool: ArqRedis) -> None:
        self.pool = pool

    @classmethod
    async def connect(cls, redis_url: str) -> Self:
        return cls(await create_pool(RedisSettings.from_dsn(redis_url)))

    async def enqueue(self, job_id: str, source_name: str, identity: VerifiedIdentity) -> None:
        await self.pool.enqueue_job(
            "run_source_job",
            _job_id=job_id,
            job_id=job_id,
            source_name=source_name,
            user_id=identity.user_id,
            email=identity.email,
        )

    async def close(self) -> None:
        await self.pool.aclose()
