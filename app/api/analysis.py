import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.deps import SettingsDep, current_identity, limit_account, limit_ip
from app.identity.types import VerifiedIdentity
from app.jobs.queue import JobQueue
from app.jobs.store import JobStatus, ResultStore
from app.schemas import StrictModel
from app.security.ratelimit import Limit
from app.sources.base import Finding
from app.sources.registry import BACKGROUND_SOURCES

router = APIRouter(prefix="/api/analysis", tags=["recolección"])


def get_store(request: Request, settings: SettingsDep) -> ResultStore:
    return ResultStore(request.app.state.redis, settings.result_ttl_seconds)


def get_queue(request: Request) -> JobQueue:
    return request.app.state.job_queue


StoreDep = Annotated[ResultStore, Depends(get_store)]


class JobStarted(StrictModel):
    job_id: str


class JobView(StrictModel):
    status: JobStatus
    findings: list[Finding]
    error: str | None


@router.post(
    "/{source_name}",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(limit_ip("analysis_start", Limit(30, 3600)))],
)
async def start_analysis(
    source_name: str,
    identity: Annotated[
        VerifiedIdentity, Depends(limit_account("analysis_start", Limit(10, 3600)))
    ],
    store: StoreDep,
    queue: Annotated[JobQueue, Depends(get_queue)],
) -> JobStarted:
    """No acepta cuerpo: el sujeto es siempre el email de la sesión verificada."""
    if source_name not in BACKGROUND_SOURCES:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Fuente desconocida.")
    job_id = secrets.token_urlsafe(16)
    await store.create(job_id, identity.user_id, source_name)
    await queue.enqueue(job_id, source_name, identity)
    return JobStarted(job_id=job_id)


@router.get("/jobs/{job_id}")
async def get_job(
    job_id: str,
    identity: Annotated[VerifiedIdentity, Depends(current_identity)],
    store: StoreDep,
) -> JobView:
    result = await store.get(job_id, identity.user_id)
    if result is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "El análisis no existe o ya venció.")
    return JobView(status=result.status, findings=result.findings, error=result.error)


@router.delete("/jobs/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_job(
    job_id: str,
    identity: Annotated[VerifiedIdentity, Depends(current_identity)],
    store: StoreDep,
) -> None:
    if await store.get(job_id, identity.user_id) is not None:
        await store.delete(job_id)
