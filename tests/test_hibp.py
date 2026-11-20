import asyncio
import time

import httpx
import pytest

from app.identity.types import VerifiedIdentity
from app.sources.base import Category, SourceError
from app.sources.hibp import HibpSource
from app.sources.pacing import RedisPacer
from tests.hibp_data import ADOBE, HIBP_URL, NEWSLETTER

ME = VerifiedIdentity(user_id=1, email="yo+test@example.com")
URL = HIBP_URL + "yo%2Btest%40example.com"


async def test_parsea_brechas(hibp_source, respx_mock):
    route = respx_mock.get(URL).respond(200, json=[ADOBE, NEWSLETTER])
    findings = await hibp_source.collect(ME)
    request = route.calls.last.request
    assert request.headers["hibp-api-key"] == "clave-hibp-de-prueba"
    assert request.headers["user-agent"] == "herramienta-osint-autoauditoria"
    assert request.url.params["truncateResponse"] == "false"
    assert [f.title for f in findings] == ["Adobe", "Boletín"]
    adobe = findings[0]
    assert adobe.category is Category.BREACHES and adobe.code == "breach.exposed"
    assert adobe.data["data_classes"] == ADOBE["DataClasses"]
    assert adobe.data["breach_date"] == "2013-10-04"
    assert adobe.detail == 'En 2013 Adobe sufrió "una brecha".'


async def test_404_significa_sin_brechas(hibp_source, respx_mock):
    respx_mock.get(URL).respond(404)
    assert await hibp_source.collect(ME) == []


async def test_429_respeta_retry_after_y_reintenta(hibp_source, respx_mock, sleeps):
    respx_mock.get(URL).mock(
        side_effect=[
            httpx.Response(429, headers={"retry-after": "3"}),
            httpx.Response(200, json=[NEWSLETTER]),
        ]
    )
    findings = await hibp_source.collect(ME)
    assert len(findings) == 1
    assert sleeps == [3.0]


async def test_errores_5xx_usan_backoff_exponencial_y_se_rinden(hibp_source, respx_mock, sleeps):
    route = respx_mock.get(URL).respond(503)
    with pytest.raises(SourceError, match="no responde"):
        await hibp_source.collect(ME)
    assert route.call_count == hibp_source.max_retries + 1
    assert len(sleeps) == hibp_source.max_retries
    base = hibp_source.base_delay
    for attempt, delay in enumerate(sleeps):
        assert base * 2**attempt <= delay <= base * 2**attempt + base


async def test_error_de_red_se_reintenta(hibp_source, respx_mock):
    respx_mock.get(URL).mock(
        side_effect=[httpx.ConnectError("caída"), httpx.Response(200, json=[ADOBE])]
    )
    assert len(await hibp_source.collect(ME)) == 1


async def test_api_key_invalida_no_reintenta(hibp_source, respx_mock):
    route = respx_mock.get(URL).respond(401)
    with pytest.raises(SourceError):
        await hibp_source.collect(ME)
    assert route.call_count == 1


async def test_sin_api_key_no_llama_a_hibp(respx_mock):
    route = respx_mock.get(URL).respond(200, json=[])
    source = HibpSource(api_key="", user_agent="ua", client=httpx.AsyncClient())
    with pytest.raises(SourceError, match="no está configurada"):
        await source.collect(ME)
    assert route.call_count == 0


async def test_pacer_espacia_llamadas_entre_workers(redis):
    pacer = RedisPacer(redis, "pace:test", 0.2)
    other_worker = RedisPacer(redis, "pace:test", 0.2)
    start = time.monotonic()
    await pacer.wait_turn()
    await other_worker.wait_turn()
    await asyncio.gather(pacer.wait_turn())
    assert time.monotonic() - start >= 0.38
