import asyncio
import logging
import random
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import quote

import httpx

from app.identity.types import VerifiedIdentity
from app.sources.base import Category, Finding, Source, SourceError
from app.sources.breach_data import data_classes_es, plain_text
from app.sources.pacing import Pacer

logger = logging.getLogger(__name__)

HIBP_API = "https://haveibeenpwned.com/api/v3"


class HibpSource(Source[None]):
    """Brechas del email verificado vía la API oficial v3 (requiere API key, sin scraping)."""

    name = "hibp"
    display_name = "Have I Been Pwned"
    homepage = "https://haveibeenpwned.com"
    category = Category.BREACHES
    runs_in_background = True

    def __init__(
        self,
        *,
        api_key: str,
        user_agent: str,
        client: httpx.AsyncClient,
        pacer: Pacer | None = None,
        max_retries: int = 4,
        base_delay: float = 2.0,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.api_key = api_key
        self.user_agent = user_agent
        self.client = client
        self.pacer = pacer
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.sleep = sleep

    async def collect(self, identity: VerifiedIdentity, payload: None = None) -> list[Finding]:
        if not self.api_key:
            raise SourceError("La consulta de filtraciones no está configurada en este servidor.")
        return [self._to_finding(breach) for breach in await self._fetch(identity.email)]

    def _backoff(self, attempt: int) -> float:
        return self.base_delay * 2**attempt + random.uniform(0, self.base_delay)  # noqa: S311

    async def _fetch(self, email: str) -> list[dict[str, Any]]:
        url = f"{HIBP_API}/breachedaccount/{quote(email, safe='')}"
        headers = {"hibp-api-key": self.api_key, "user-agent": self.user_agent}
        for attempt in range(self.max_retries + 1):
            if self.pacer is not None:
                await self.pacer.wait_turn()
            try:
                response = await self.client.get(
                    url, params={"truncateResponse": "false"}, headers=headers, timeout=15
                )
            except httpx.TransportError:
                delay = self._backoff(attempt)
            else:
                if response.status_code == 200:
                    return response.json()
                if response.status_code == 404:
                    return []
                if response.status_code in (401, 403):
                    logger.error("HIBP rechazó la petición: %s", response.status_code)
                    raise SourceError(
                        "El servicio de filtraciones rechazó la configuración del servidor."
                    )
                if response.status_code == 429:
                    delay = self._retry_after(response) or self._backoff(attempt)
                elif response.status_code >= 500:
                    delay = self._backoff(attempt)
                else:
                    raise SourceError(
                        f"Respuesta inesperada de Have I Been Pwned ({response.status_code})."
                    )
            if attempt < self.max_retries:
                await self.sleep(delay)
        raise SourceError("Have I Been Pwned no responde en este momento. Probá más tarde.")

    @staticmethod
    def _retry_after(response: httpx.Response) -> float | None:
        try:
            return float(response.headers["retry-after"])
        except (KeyError, ValueError):
            return None

    def _to_finding(self, breach: dict[str, Any]) -> Finding:
        return Finding(
            source=self.name,
            category=self.category,
            code="breach.exposed",
            title=breach.get("Title") or breach.get("Name", "Filtración"),
            detail=plain_text(breach.get("Description", ""))[:5000],
            data={
                "name": breach.get("Name"),
                "domain": breach.get("Domain") or None,
                "breach_date": breach.get("BreachDate"),
                "added_date": breach.get("AddedDate"),
                "pwn_count": breach.get("PwnCount"),
                "data_classes": list(breach.get("DataClasses", [])),
                "data_classes_es": data_classes_es(breach.get("DataClasses", [])),
                "is_verified": breach.get("IsVerified", False),
                "is_sensitive": breach.get("IsSensitive", False),
                "is_fabricated": breach.get("IsFabricated", False),
                "is_spam_list": breach.get("IsSpamList", False),
                "is_stealer_log": breach.get("IsStealerLog", False),
            },
        )
