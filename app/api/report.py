from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import Field, model_validator

from app.analysis.risk import assess
from app.api.analysis import StoreDep
from app.deps import limit_account
from app.identity.types import VerifiedIdentity
from app.jobs.store import JobStatus
from app.report.builder import Report, build_report
from app.schemas import StrictModel
from app.security.ratelimit import Limit
from app.sources.base import Category, Finding
from app.sources.exif import ExifSource
from app.sources.pwned_passwords import PasswordCheck, PwnedPasswordsSource

router = APIRouter(prefix="/api/report", tags=["informe"])

passwords_source = PwnedPasswordsSource()


class ReportRequest(StrictModel):
    breach_job_id: str | None = Field(default=None, max_length=64)
    password_checks: list[PasswordCheck] | None = Field(default=None, max_length=20)
    photo_findings: list[Finding] | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _not_empty(self) -> "ReportRequest":
        if self.breach_job_id is None and not self.password_checks and not self.photo_findings:
            raise ValueError("No hay nada para incluir en el informe.")
        for finding in self.photo_findings or []:
            if finding.category is not Category.PHOTOS or finding.source != ExifSource.name:
                raise ValueError("photo_findings solo admite hallazgos de fotos.")
        return self


@router.post("")
async def create_report(
    body: ReportRequest,
    identity: Annotated[VerifiedIdentity, Depends(limit_account("report", Limit(30, 3600)))],
    store: StoreDep,
) -> Report:
    findings: dict[Category, list[Finding] | None] = {}
    if body.breach_job_id is not None:
        job = await store.get(body.breach_job_id, identity.user_id)
        if job is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                "El análisis de filtraciones venció. Volvé a lanzarlo para incluirlo.",
            )
        if job.status is JobStatus.PENDING:
            raise HTTPException(status.HTTP_409_CONFLICT, "El análisis todavía está en curso.")
        if job.status is JobStatus.FAILED:
            raise HTTPException(status.HTTP_409_CONFLICT, job.error or "El análisis falló.")
        findings[Category.BREACHES] = job.findings
    if body.password_checks:
        findings[Category.PASSWORDS] = await passwords_source.collect(
            identity, body.password_checks
        )
    if body.photo_findings:
        findings[Category.PHOTOS] = body.photo_findings
    return build_report(identity, assess(findings))
