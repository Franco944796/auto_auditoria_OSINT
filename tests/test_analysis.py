from tests.conftest import login, post
from tests.hibp_data import ADOBE, HIBP_URL

URL_YO = HIBP_URL + "yo%40example.com"


def _start(client, source="hibp"):
    return post(client, f"/api/analysis/{source}")


def test_flujo_completo_de_filtraciones(client, mailer, respx_mock):
    respx_mock.get(URL_YO).respond(200, json=[ADOBE])
    login(client, mailer)
    response = _start(client)
    assert response.status_code == 202
    job = client.get(f"/api/analysis/jobs/{response.json()['job_id']}").json()
    assert job["status"] == "done"
    assert job["findings"][0]["title"] == "Adobe"
    assert job["error"] is None


def test_otro_usuario_no_puede_leer_el_resultado(app, client, mailer, respx_mock):
    respx_mock.get(URL_YO).respond(200, json=[ADOBE])
    login(client, mailer)
    job_id = _start(client).json()["job_id"]
    client.cookies.clear()
    login(client, mailer, "otra@example.com")
    assert client.get(f"/api/analysis/jobs/{job_id}").status_code == 404


def test_fuente_desconocida_o_no_de_fondo_da_404(client, mailer):
    login(client, mailer)
    assert _start(client, "inventada").status_code == 404
    assert _start(client, "pwned_passwords").status_code == 404


def test_fallo_de_la_fuente_se_informa(client, mailer, respx_mock):
    respx_mock.get(URL_YO).respond(401)
    login(client, mailer)
    job = client.get(f"/api/analysis/jobs/{_start(client).json()['job_id']}").json()
    assert job["status"] == "failed"
    assert "rechazó" in job["error"]


def test_resultados_vencen_solos(client, mailer, respx_mock, redis, settings):
    respx_mock.get(URL_YO).respond(200, json=[ADOBE])
    login(client, mailer)
    job_id = _start(client).json()["job_id"]
    # El Redis falso quedó atado al event loop del TestClient.
    ttl = client.portal.call(redis.ttl, f"job:{job_id}")
    assert 0 < ttl <= settings.result_ttl_seconds


def test_limite_por_cuenta_en_analisis(client, mailer, respx_mock):
    respx_mock.get(URL_YO).respond(404)
    login(client, mailer)
    statuses = [_start(client).status_code for _ in range(11)]
    assert statuses[:10] == [202] * 10
    assert statuses[10] == 429


def test_borrar_resultado_del_analisis(client, mailer, respx_mock):
    respx_mock.get(URL_YO).respond(404)
    login(client, mailer)
    job_id = _start(client).json()["job_id"]
    headers = {"X-CSRF-Token": client.cookies["csrf_token"]}
    assert client.delete(f"/api/analysis/jobs/{job_id}", headers=headers).status_code == 204
    assert client.get(f"/api/analysis/jobs/{job_id}").status_code == 404
