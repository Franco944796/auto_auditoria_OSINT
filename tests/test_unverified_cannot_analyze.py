"""Requisito central: nunca se analiza un email que el usuario no haya verificado."""

from datetime import timedelta

from app.db import utcnow
from app.identity.service import SESSION
from app.identity.tokens import hash_token
from app.models import Session, User
from tests.conftest import login, post


def test_sin_sesion_no_se_puede_lanzar_un_analisis(client, job_queue, respx_mock):
    response = post(client, "/api/analysis/hibp")
    assert response.status_code == 401
    assert job_queue.calls == []
    assert len(respx_mock.calls) == 0


def test_email_con_verificacion_pendiente_no_se_puede_analizar(client, job_queue):
    assert post(client, "/api/auth/start", json={"email": "yo@example.com"}).status_code == 202
    assert post(client, "/api/analysis/hibp").status_code == 401
    assert job_queue.calls == []


async def test_sesion_de_usuario_no_verificado_es_rechazada(app, client, job_queue, settings):
    raw = "sesion-forjada-" + "x" * 30
    async with app.state.sessionmaker() as db:
        user = User(email="victima@example.com")
        db.add(user)
        await db.flush()
        db.add(
            Session(
                user_id=user.id,
                token_hash=hash_token(settings.secret_key.get_secret_value(), SESSION, raw),
                expires_at=utcnow() + timedelta(hours=1),
            )
        )
        await db.commit()
    client.cookies.set("session", raw)
    assert post(client, "/api/analysis/hibp").status_code == 401
    assert job_queue.calls == []


def test_no_se_puede_indicar_otro_email_en_la_peticion(client, mailer, job_queue, respx_mock):
    respx_mock.get(url__startswith="https://haveibeenpwned.com/").respond(404)
    login(client, mailer, "yo@example.com")
    post(client, "/api/analysis/hibp", json={"email": "victima@example.com"})
    post(client, "/api/analysis/hibp?email=victima@example.com")
    assert [identity.email for _, _, identity in job_queue.calls] == ["yo@example.com"] * 2
    assert all("victima" not in str(call.request.url) for call in respx_mock.calls)
