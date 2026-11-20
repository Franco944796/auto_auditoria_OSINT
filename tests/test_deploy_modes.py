import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from app.analysis.rules import assess_finding
from app.config import Settings
from app.identity.mailer import BrevoMailer, build_mailer
from app.main import create_app
from app.sources.base import Category, Finding
from app.sources.registry import enabled_background_sources, enabled_breach_source
from app.sources.xposedornot import XON_API
from tests.conftest import BASE_URL, login, post


def _settings(settings: Settings, **changes) -> Settings:
    return settings.model_copy(update=changes)


def test_fuente_de_filtraciones_automatica(settings):
    assert enabled_breach_source(settings).name == "hibp"
    without_key = _settings(settings, hibp_api_key=type(settings.hibp_api_key)(""))
    assert enabled_breach_source(without_key).name == "xposedornot"
    forced = _settings(settings, breach_source="xposedornot")
    assert enabled_background_sources(forced) == frozenset({"xposedornot"})


@pytest.fixture
def demo_settings(settings):
    return _settings(
        settings,
        hibp_api_key=type(settings.hibp_api_key)(""),
        job_backend="inprocess",
    )


def test_demo_gratuita_de_punta_a_punta(demo_settings, redis, mailer, respx_mock):
    respx_mock.get(XON_API).respond(
        200,
        json={
            "ExposedBreaches": {
                "breaches_details": [
                    {"breach": "Ejemplo", "xposed_data": "Email addresses", "xposed_date": "2020"}
                ]
            }
        },
    )
    app = create_app(demo_settings, redis=redis, mailer=mailer)
    with TestClient(app, base_url=BASE_URL) as client:
        assert "XposedOrNot" in client.get("/panel").text
        login(client, mailer)
        assert post(client, "/api/analysis/hibp").status_code == 404
        job_id = post(client, "/api/analysis/xposedornot").json()["job_id"]
        job = {"status": "pending"}
        deadline = time.monotonic() + 5
        while job["status"] == "pending" and time.monotonic() < deadline:
            job = client.get(f"/api/analysis/jobs/{job_id}").json()
        assert job["status"] == "done"
        assert job["findings"][0]["title"] == "Ejemplo"
        report = post(client, "/api/report", json={"breach_job_id": job_id}).json()
        assert report["attributions"] == ["Datos de filtraciones: XposedOrNot (xposedornot.com)."]


def test_privacidad_nombra_al_proveedor_configurado(demo_settings, redis, mailer):
    app = create_app(demo_settings, redis=redis, mailer=mailer)
    with TestClient(app, base_url=BASE_URL) as client:
        text = client.get("/privacidad").text
    assert "XposedOrNot" in text and "Have I Been Pwned</strong> (haveibeenpwned.com)" not in text


def test_paso_extra_si_la_contrasena_se_filtro_sin_cifrar():
    finding = Finding(
        source="xposedornot",
        category=Category.BREACHES,
        code="breach.exposed",
        title="Sitio",
        data={"data_classes": ["Passwords"], "password_risk": "plaintext"},
    )
    assert "sin cifrar" in assess_finding(finding).remediation[0]


async def test_brevo_envia_por_api(settings, respx_mock):
    configured = _settings(
        settings,
        mail_backend="brevo",
        brevo_api_key=type(settings.brevo_api_key)("xkeysib-prueba"),
        mail_from="Autoauditoría <yo@example.com>",
    )
    assert isinstance(build_mailer(configured), BrevoMailer)
    route = respx_mock.post(BrevoMailer.API_URL).respond(201, json={"messageId": "<1@x>"})
    await BrevoMailer(configured, httpx.AsyncClient()).send("a@example.com", "Asunto", "Cuerpo")
    request = route.calls.last.request
    assert request.headers["api-key"] == "xkeysib-prueba"
    assert json.loads(request.content) == {
        "sender": {"name": "Autoauditoría", "email": "yo@example.com"},
        "to": [{"email": "a@example.com"}],
        "subject": "Asunto",
        "textContent": "Cuerpo",
    }


async def test_brevo_error_se_propaga(settings, respx_mock):
    configured = _settings(settings, brevo_api_key=type(settings.brevo_api_key)("k"))
    respx_mock.post(BrevoMailer.API_URL).respond(400, json={"code": "unauthorized"})
    with pytest.raises(RuntimeError, match="400"):
        await BrevoMailer(configured, httpx.AsyncClient()).send("a@example.com", "s", "b")
