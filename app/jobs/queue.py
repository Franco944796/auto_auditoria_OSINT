from typing import Protocol, Self

from arq import create_pool
from arq.connections import ArqRedis, RedisSettings

from app.identity.types import VerifiedIdentity


class JobQueue(Protocol):
    async def enqueue(self, job_id: str, source_name: str, identity: VerifiedIdentity) -> None: ...

    async def close(self) -> None: ...


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
