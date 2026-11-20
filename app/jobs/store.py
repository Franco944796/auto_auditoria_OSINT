from enum import StrEnum

from pydantic import BaseModel
from redis.asyncio import Redis

from app.sources.base import Finding


class JobStatus(StrEnum):
    PENDING = "pending"
    DONE = "done"
    FAILED = "failed"


class JobResult(BaseModel):
    owner_id: int
    source: str
    status: JobStatus = JobStatus.PENDING
    findings: list[Finding] = []
    error: str | None = None


class ResultStore:
    """Resultados efímeros: viven en Redis (sin persistencia en disco) y vencen solos."""

    def __init__(self, redis: Redis, ttl_seconds: int) -> None:
        self.redis = redis
        self.ttl_seconds = ttl_seconds

    @staticmethod
    def _key(job_id: str) -> str:
        return f"job:{job_id}"

    async def create(self, job_id: str, owner_id: int, source: str) -> None:
        result = JobResult(owner_id=owner_id, source=source)
        await self.redis.set(self._key(job_id), result.model_dump_json(), ex=self.ttl_seconds)

    async def _load(self, job_id: str) -> JobResult | None:
        raw = await self.redis.get(self._key(job_id))
        return JobResult.model_validate_json(raw) if raw else None

    async def _save(self, job_id: str, result: JobResult) -> None:
        # xx + keepttl: si el resultado ya venció, no se recrea ni se le extiende la vida.
        await self.redis.set(self._key(job_id), result.model_dump_json(), xx=True, keepttl=True)

    async def complete(self, job_id: str, findings: list[Finding]) -> None:
        result = await self._load(job_id)
        if result is not None:
            result.status, result.findings = JobStatus.DONE, findings
            await self._save(job_id, result)

    async def fail(self, job_id: str, message: str) -> None:
        result = await self._load(job_id)
        if result is not None:
            result.status, result.error = JobStatus.FAILED, message
            await self._save(job_id, result)

    async def get(self, job_id: str, owner_id: int) -> JobResult | None:
        result = await self._load(job_id)
        if result is None or result.owner_id != owner_id:
            return None
        return result

    async def delete(self, job_id: str) -> None:
        await self.redis.delete(self._key(job_id))
