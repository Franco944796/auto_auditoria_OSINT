from datetime import datetime

from pydantic import BaseModel

from app.analysis.risk import CategoryAssessment, RiskLevel, overall_level
from app.db import utcnow
from app.identity.types import VerifiedIdentity


class Report(BaseModel):
    """Se arma en memoria, se devuelve y se descarta: no hay tabla de informes."""

    generated_at: datetime
    email: str
    overall_level: RiskLevel | None
    categories: list[CategoryAssessment]
    attributions: list[str]


# La licencia de HIBP (CC BY 4.0) y los términos de XposedOrNot exigen citar la fuente.
ATTRIBUTIONS = {
    "hibp": "Datos de filtraciones: Have I Been Pwned (haveibeenpwned.com), licencia CC BY 4.0.",
    "xposedornot": "Datos de filtraciones: XposedOrNot (xposedornot.com).",
    "pwned_passwords": (
        "Contraseñas: Pwned Passwords de Have I Been Pwned, consultado desde tu navegador "
        "con k-anonimidad."
    ),
}


def build_report(
    identity: VerifiedIdentity, categories: list[CategoryAssessment], sources_used: list[str]
) -> Report:
    return Report(
        generated_at=utcnow(),
        email=identity.email,
        overall_level=overall_level(categories),
        categories=categories,
        attributions=[ATTRIBUTIONS[name] for name in sources_used if name in ATTRIBUTIONS],
    )
