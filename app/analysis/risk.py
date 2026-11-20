from collections.abc import Callable
from enum import StrEnum
from typing import Any

from pydantic import BaseModel

from app.analysis.rules import SEVERITY_RANK, Severity, assess_finding
from app.sources.base import Category, Finding


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AssessedFinding(BaseModel):
    source: str
    code: str
    title: str
    detail: str
    data: dict[str, Any]
    severity: Severity
    remediation: list[str]


class CategoryAssessment(BaseModel):
    category: Category
    label: str
    evaluated: bool
    level: RiskLevel | None
    summary: str
    findings: list[AssessedFinding]


CATEGORY_LABELS = {
    Category.BREACHES: "Filtraciones de datos",
    Category.PASSWORDS: "Contraseñas",
    Category.PHOTOS: "Metadatos de fotos",
}
CATEGORY_ORDER = [Category.BREACHES, Category.PASSWORDS, Category.PHOTOS]


def _plural(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def _summary_breaches(findings: list[Finding]) -> str:
    if not findings:
        return "Tu email no aparece en ninguna filtración conocida por Have I Been Pwned."
    return f"Tu email aparece en {_plural(len(findings), 'filtración', 'filtraciones')}."


def _summary_passwords(findings: list[Finding]) -> str:
    exposed = sum(1 for f in findings if f.code == "password.compromised")
    checked = _plural(len(findings), "contraseña", "contraseñas")
    if not exposed:
        return f"Revisaste {checked} y ninguna aparece en filtraciones conocidas."
    verb = "aparece" if exposed == 1 else "aparecen"
    return f"Revisaste {checked}: {exposed} {verb} en filtraciones conocidas."


def _summary_photos(findings: list[Finding]) -> str:
    photos = {f.data.get("photo") for f in findings}
    with_gps = len({f.data.get("photo") for f in findings if f.code == "exif.gps"})
    checked = _plural(len(photos), "foto", "fotos")
    if not with_gps:
        return f"Revisaste {checked} y ninguna revela la ubicación exacta."
    verb = "revela" if with_gps == 1 else "revelan"
    return f"Revisaste {checked}: {with_gps} {verb} la ubicación exacta."


SUMMARIES: dict[Category, Callable[[list[Finding]], str]] = {
    Category.BREACHES: _summary_breaches,
    Category.PASSWORDS: _summary_passwords,
    Category.PHOTOS: _summary_photos,
}


def _level(findings: list[AssessedFinding]) -> RiskLevel:
    top = max((SEVERITY_RANK[f.severity] for f in findings), default=0)
    if top >= SEVERITY_RANK[Severity.HIGH]:
        return RiskLevel.HIGH
    if top == SEVERITY_RANK[Severity.MEDIUM]:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def assess_category(category: Category, findings: list[Finding] | None) -> CategoryAssessment:
    label = CATEGORY_LABELS[category]
    if findings is None:
        return CategoryAssessment(
            category=category,
            label=label,
            evaluated=False,
            level=None,
            summary="No se revisó en este informe.",
            findings=[],
        )
    assessed = []
    for finding in findings:
        assessment = assess_finding(finding)
        assessed.append(
            AssessedFinding(
                **finding.model_dump(exclude={"category"}),
                severity=assessment.severity,
                remediation=assessment.remediation,
            )
        )
    assessed.sort(key=lambda f: SEVERITY_RANK[f.severity], reverse=True)
    return CategoryAssessment(
        category=category,
        label=label,
        evaluated=True,
        level=_level(assessed),
        summary=SUMMARIES[category](findings),
        findings=assessed,
    )


def assess(findings: dict[Category, list[Finding] | None]) -> list[CategoryAssessment]:
    return [assess_category(category, findings.get(category)) for category in CATEGORY_ORDER]


LEVEL_RANK = {RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3}


def overall_level(categories: list[CategoryAssessment]) -> RiskLevel | None:
    levels = [c.level for c in categories if c.level is not None]
    return max(levels, key=LEVEL_RANK.__getitem__) if levels else None
