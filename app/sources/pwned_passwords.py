from pydantic import Field

from app.identity.types import VerifiedIdentity
from app.schemas import StrictModel
from app.sources.base import Category, Finding, Source


class PasswordCheck(StrictModel):
    label: str = Field(min_length=1, max_length=40)
    times_seen: int = Field(ge=0)


def _describe(times_seen: int) -> str:
    if not times_seen:
        return "No aparece en filtraciones conocidas."
    count = f"{times_seen:,}".replace(",", ".")
    return f"Apareció {count} {'vez' if times_seen == 1 else 'veces'} en filtraciones conocidas."


class PwnedPasswordsSource(Source[list[PasswordCheck]]):
    """La consulta con k-anonimidad la hace el navegador (static/js/passwords.js): el backend
    solo recibe cuántas veces apareció cada contraseña, nunca la contraseña ni su hash."""

    name = "pwned_passwords"
    category = Category.PASSWORDS

    async def collect(
        self, identity: VerifiedIdentity, payload: list[PasswordCheck]
    ) -> list[Finding]:
        return [
            Finding(
                source=self.name,
                category=self.category,
                code="password.compromised" if check.times_seen else "password.clean",
                title=check.label,
                detail=_describe(check.times_seen),
                data={"times_seen": check.times_seen},
            )
            for check in payload
        ]
