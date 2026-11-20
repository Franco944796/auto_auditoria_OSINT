from tests.conftest import login, post
from tests.hibp_data import ADOBE, HIBP_URL

URL_YO = HIBP_URL + "yo%40example.com"

PHOTO_FINDING = {
    "source": "exif",
    "category": "photos",
    "code": "exif.gps",
    "title": "Ubicación GPS exacta",
    "detail": "La foto guarda dónde se tomó: -34.6, -58.38.",
    "data": {"photo": "casa.jpg", "latitude": -34.6, "longitude": -58.38},
}


def _report(client, body):
    return post(client, "/api/report", json=body)


def test_informe_completo(client, mailer, respx_mock):
    respx_mock.get(URL_YO).respond(200, json=[ADOBE])
    login(client, mailer)
    job_id = post(client, "/api/analysis/hibp").json()["job_id"]
    response = _report(
        client,
        {
            "breach_job_id": job_id,
            "password_checks": [
                {"label": "Contraseña 1", "times_seen": 52},
                {"label": "Contraseña 2", "times_seen": 0},
            ],
            "photo_findings": [PHOTO_FINDING],
        },
    )
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["email"] == "yo@example.com"
    assert report["overall_level"] == "high"
    categories = {c["category"]: c for c in report["categories"]}
    assert categories["breaches"]["level"] == "high"
    assert categories["breaches"]["findings"][0]["remediation"]
    assert categories["passwords"]["summary"].startswith("Revisaste 2 contraseñas: 1")
    assert categories["passwords"]["findings"][0]["detail"] == (
        "Apareció 52 veces en filtraciones conocidas."
    )
    assert categories["photos"]["level"] == "high"
    assert any("CC BY 4.0" in a for a in report["attributions"])
    assert response.headers["cache-control"] == "no-store"


def test_informe_parcial_marca_categorias_no_revisadas(client, mailer):
    login(client, mailer)
    report = _report(client, {"password_checks": [{"label": "C1", "times_seen": 0}]}).json()
    categories = {c["category"]: c for c in report["categories"]}
    assert categories["breaches"]["evaluated"] is False
    assert categories["passwords"]["level"] == "low"
    assert report["overall_level"] == "low"


def test_informe_vacio_rechazado(client, mailer):
    login(client, mailer)
    assert _report(client, {}).status_code == 422


def test_informe_no_acepta_contrasenas_ni_hashes(client, mailer):
    login(client, mailer)
    body = {"password_checks": [{"label": "C1", "times_seen": 1, "password": "hunter2"}]}
    assert _report(client, body).status_code == 422
    body = {"password_checks": [{"label": "C1", "times_seen": 1}], "sha1": "ABCDE"}
    assert _report(client, body).status_code == 422


def test_informe_rechaza_hallazgos_que_no_son_de_fotos(client, mailer):
    login(client, mailer)
    fake = {**PHOTO_FINDING, "source": "hibp", "category": "breaches"}
    assert _report(client, {"photo_findings": [fake]}).status_code == 422


def test_informe_con_job_ajeno_o_vencido_da_404(client, mailer):
    login(client, mailer)
    assert _report(client, {"breach_job_id": "no-existe"}).status_code == 404


def test_informe_requiere_email_verificado(client):
    assert _report(client, {"photo_findings": [PHOTO_FINDING]}).status_code == 401


async def test_informe_no_se_persiste(app, client, mailer):
    from sqlalchemy import inspect

    login(client, mailer)
    _report(client, {"photo_findings": [PHOTO_FINDING]})
    engine = app.state.sessionmaker.kw["bind"]
    async with engine.connect() as conn:
        tables = await conn.run_sync(lambda sync: inspect(sync).get_table_names())
    assert set(tables) == {"users", "verification_tokens", "sessions"}
