from fastapi.testclient import TestClient

from app.main import create_app
from tests.conftest import csrf, post


def test_cabeceras_de_seguridad(client):
    response = client.get("/api/me")
    headers = response.headers
    csp = headers["content-security-policy"]
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp
    assert headers["strict-transport-security"].startswith("max-age=")
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["x-frame-options"] == "DENY"
    assert headers["cache-control"] == "no-store"


def test_post_sin_token_csrf_rechazado(client):
    response = client.post("/api/auth/start", json={"email": "yo@example.com"})
    assert response.status_code == 403


def test_post_con_token_csrf_distinto_rechazado(client):
    csrf(client)
    response = client.post(
        "/api/auth/start", json={"email": "yo@example.com"}, headers={"X-CSRF-Token": "otro"}
    )
    assert response.status_code == 403


def test_post_desde_otro_origen_rechazado(client):
    response = post(
        client,
        "/api/auth/start",
        json={"email": "yo@example.com"},
        headers={"Origin": "https://atacante.example"},
    )
    assert response.status_code == 403


def test_post_desde_el_mismo_origen_aceptado(client):
    response = post(
        client,
        "/api/auth/start",
        json={"email": "yo@example.com"},
        headers={"Origin": "https://testserver"},
    )
    assert response.status_code == 202


def test_cookie_csrf_es_segura_y_strict(client):
    set_cookie = client.get("/api/me").headers["set-cookie"].lower()
    assert "csrf_token=" in set_cookie and "secure" in set_cookie
    assert "samesite=strict" in set_cookie


def test_limite_por_cuenta_en_inicio_de_verificacion(client):
    statuses = [
        post(client, "/api/auth/start", json={"email": "yo@example.com"}).status_code
        for _ in range(4)
    ]
    assert statuses == [202, 202, 202, 429]


def test_limite_por_ip_en_inicio_de_verificacion(client):
    statuses = [
        post(client, "/api/auth/start", json={"email": f"yo{i}@example.com"}).status_code
        for i in range(11)
    ]
    assert statuses[:10] == [202] * 10
    assert statuses[10] == 429


def test_respuesta_429_trae_retry_after(client):
    for _ in range(3):
        post(client, "/api/auth/start", json={"email": "yo@example.com"})
    response = post(client, "/api/auth/start", json={"email": "yo@example.com"})
    assert response.status_code == 429
    assert int(response.headers["retry-after"]) >= 1


def test_limite_global_por_ip(settings, redis, mailer, job_queue):
    settings.rate_limit_global_per_minute = 3
    app = create_app(settings, redis=redis, mailer=mailer, job_queue=job_queue)
    with TestClient(app, base_url="https://testserver") as client:
        statuses = [client.get("/api/me").status_code for _ in range(4)]
    assert statuses == [401, 401, 401, 429]


def test_http_redirige_a_https(app):
    with TestClient(app, base_url="http://testserver") as client:
        response = client.get("/api/me", follow_redirects=False)
        assert response.status_code == 308
        assert response.headers["location"].startswith("https://")
        assert client.get("/healthz").status_code == 200
