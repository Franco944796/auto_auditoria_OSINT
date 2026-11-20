import asyncio
import logging
import random
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from app.identity.types import VerifiedIdentity
from app.security.ratelimit import Limit, RateLimiter, RateLimitExceeded
from app.sources.base import Category, Finding, Source, SourceError
from app.sources.breach_data import data_classes_es, plain_text
from app.sources.pacing import Pacer

logger = logging.getLogger(__name__)

XON_API = "https://api.xposedornot.com/v1/breach-analytics"
# Cupo gratuito publicado por XposedOrNot para breach-analytics, por IP. Sus términos exigen
# respetarlo, así que se controla antes de llamar en lugar de esperar al 429.
FREE_QUOTA = (Limit(25, 3600), Limit(100, 86400))
QUOTA_EXHAUSTED = (
    "Se alcanzó el límite gratuito de consultas de filtraciones por hoy. Probá más tarde."
)


class XposedOrNotSource(Source[None]):
    """Brechas del email verificado vía la API pública de XposedOrNot (sin API key).
    El plan gratuito es para uso personal y de bajo volumen: un uso comercial requiere licencia."""

    name = "xposedornot"
    display_name = "XposedOrNot"
    homepage = "https://xposedornot.com"
    category = Category.BREACHES
    runs_in_background = True

    def __init__(
        self,
        *,
        client: httpx.AsyncClient,
        user_agent: str,
        pacer: Pacer | None = None,
        quota: RateLimiter | None = None,
        max_retries: int = 3,
        base_delay: float = 2.0,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.client = client
        self.user_agent = user_agent
        self.pacer = pacer
        self.quota = quota
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.sleep = sleep

    async def collect(self, identity: VerifiedIdentity, payload: None = None) -> list[Finding]:
        if self.quota is not None:
            try:
                for limit in FREE_QUOTA:
                    await self.quota.hit("source:xposedornot", limit)
            except RateLimitExceeded as exc:
                raise SourceError(QUOTA_EXHAUSTED) from exc
        data = await self._fetch(identity.email)
        exposed = data.get("ExposedBreaches") or {}
        return [self._to_finding(breach) for breach in exposed.get("breaches_details") or []]

    def _backoff(self, attempt: int) -> float:
        return self.base_delay * 2**attempt + random.uniform(0, self.base_delay)  # noqa: S311

    async def _fetch(self, email: str) -> dict[str, Any]:
        for attempt in range(self.max_retries + 1):
            if self.pacer is not None:
                await self.pacer.wait_turn()
            try:
                response = await self.client.get(
                    XON_API,
                    params={"email": email},
                    headers={"user-agent": self.user_agent},
                    timeout=20,
                )
            except httpx.TransportError:
                delay = self._backoff(attempt)
            else:
                if response.status_code == 200:
                    return response.json() or {}
                if response.status_code == 404:
                    return {}
                if response.status_code == 429:
                    # Su 429 es un cupo horario o diario: reintentar enseguida no sirve.
                    raise SourceError(QUOTA_EXHAUSTED)
                if response.status_code >= 500:
                    delay = self._backoff(attempt)
                else:
                    logger.error("XposedOrNot respondió %s", response.status_code)
                    raise SourceError(
                        f"Respuesta inesperada de XposedOrNot ({response.status_code})."
                    )
            if attempt < self.max_retries:
                await self.sleep(delay)
        raise SourceError("XposedOrNot no responde en este momento. Probá más tarde.")

    def _to_finding(self, breach: dict[str, Any]) -> Finding:
        classes = [c.strip() for c in (breach.get("xposed_data") or "").split(";") if c.strip()]
        return Finding(
            source=self.name,
            category=self.category,
            code="breach.exposed",
            title=breach.get("breach") or "Filtración",
            detail=plain_text(breach.get("details") or "")[:5000],
            data={
                "name": breach.get("breach"),
                "domain": breach.get("domain") or None,
                "breach_date": str(breach.get("xposed_date") or "") or None,
                "pwn_count": breach.get("xposed_records"),
                "data_classes": classes,
                "data_classes_es": data_classes_es(classes),
                "is_verified": breach.get("verified") == "Yes",
                "password_risk": breach.get("password_risk") or None,
            },
        )
