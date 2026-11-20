from datetime import datetime

from pydantic import BaseModel

from app.analysis.risk import CategoryAssessment, RiskLevel, overall_level
from app.db import utcnow
from app.identity.types import VerifiedIdentity
from app.sources.base import Category


class Report(BaseModel):
    """Se arma en memoria, se devuelve y se descarta: no hay tabla de informes."""

    generated_at: datetime
    email: str
    overall_level: RiskLevel | None
    categories: list[CategoryAssessment]
    attributions: list[str]


ATTRIBUTIONS = {
    Category.BREACHES: (
        "Datos de filtraciones: Have I Been Pwned (haveibeenpwned.com), licencia CC BY 4.0."
    ),
    Category.PASSWORDS: (
        "Contraseñas: Pwned Passwords de Have I Been Pwned, consultado desde tu navegador "
        "con k-anonimidad."
    ),
}


def build_report(identity: VerifiedIdentity, categories: list[CategoryAssessment]) -> Report:
    return Report(
        generated_at=utcnow(),
        email=identity.email,
        overall_level=overall_level(categories),
        categories=categories,
        attributions=[
            ATTRIBUTIONS[c.category]
            for c in categories
            if c.evaluated and c.category in ATTRIBUTIONS
        ],
    )
