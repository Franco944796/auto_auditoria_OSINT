from datetime import timedelta

from sqlalchemy import select, update

from app.db import utcnow
from app.models import Session, User, VerificationToken
from tests.conftest import login, post

EMAIL = "Yo@Example.com"


async def _tokens(app) -> list[VerificationToken]:
    async with app.state.sessionmaker() as db:
        return list(await db.scalars(select(VerificationToken)))


def _start(client, email=EMAIL):
    return post(client, "/api/auth/start", json={"email": email})


def _verify(client, code, email=EMAIL):
    return post(client, "/api/auth/verify-code", json={"email": email, "code": code})


def test_start_envia_codigo_y_enlace_con_respuesta_generica(client, mailer):
    response = _start(client)
    assert response.status_code == 202
    assert "Si el email es válido" in response.json()["detail"]
    to, subject, body = mailer.sent[-1]
    assert to == "yo@example.com"
    assert mailer.last_otp() in subject
    assert "/verificar#t=" in body
    assert "15 minutos" in body


def test_codigo_correcto_abre_sesion(client, mailer):
    _start(client)
    response = _verify(client, mailer.last_otp())
    assert response.status_code == 200
    assert response.json() == {"email": "yo@example.com"}
    set_cookie = response.headers["set-cookie"].lower()
    assert "httponly" in set_cookie and "secure" in set_cookie and "samesite=strict" in set_cookie
    assert client.get("/api/me").json() == {"email": "yo@example.com"}


def test_sin_sesion_me_devuelve_401(client):
    assert client.get("/api/me").status_code == 401


def test_estado_de_sesion(client, mailer):
    assert client.get("/api/session").json() == {"authenticated": False}
    login(client, mailer)
    assert client.get("/api/session").json() == {"authenticated": True}


def test_codigo_incorrecto_rechazado(client, mailer):
    _start(client)
    wrong = "000000" if mailer.last_otp() != "000000" else "111111"
    assert _verify(client, wrong).status_code == 400
    assert client.get("/api/me").status_code == 401


def test_codigo_se_invalida_tras_maximo_de_intentos(client, mailer, settings):
    _start(client)
    good = mailer.last_otp()
    wrong = "000000" if good != "000000" else "111111"
    for _ in range(settings.verification_max_attempts):
        assert _verify(client, wrong).status_code == 400
    assert _verify(client, good).status_code == 400


async def test_codigo_vencido_rechazado(client, mailer, app):
    _start(client)
    async with app.state.sessionmaker() as db:
        await db.execute(
            update(VerificationToken).values(expires_at=utcnow() - timedelta(seconds=1))
        )
        await db.commit()
    assert _verify(client, mailer.last_otp()).status_code == 400


async def test_codigo_vence_a_los_15_minutos(client, app):
    _start(client)
    token = (await _tokens(app))[0]
    ttl = token.expires_at - token.created_at
    assert timedelta(minutes=14, seconds=59) <= ttl <= timedelta(minutes=15, seconds=1)


def test_codigo_es_de_un_solo_uso(client, mailer):
    _start(client)
    code = mailer.last_otp()
    assert _verify(client, code).status_code == 200
    assert _verify(client, code).status_code == 400


def test_pedir_codigo_nuevo_anula_el_anterior(client, mailer):
    _start(client)
    first = mailer.last_otp()
    _start(client)
    second = mailer.last_otp()
    if first != second:
        assert _verify(client, first).status_code == 400
    assert _verify(client, second).status_code == 200


def test_magic_link_verifica_una_sola_vez(client, mailer):
    _start(client)
    token = mailer.last_link_token()
    assert client.get("/verificar").status_code == 200
    assert post(client, "/api/auth/verify-link", json={"token": token}).status_code == 200
    assert client.get("/api/me").status_code == 200
    assert post(client, "/api/auth/verify-link", json={"token": token}).status_code == 400


def test_usar_el_enlace_consume_tambien_el_codigo(client, mailer):
    _start(client)
    code, token = mailer.last_otp(), mailer.last_link_token()
    assert post(client, "/api/auth/verify-link", json={"token": token}).status_code == 200
    assert _verify(client, code).status_code == 400


async def test_tokens_se_guardan_hasheados(client, mailer, app):
    _start(client)
    code, token = mailer.last_otp(), mailer.last_link_token()
    _verify(client, code)
    session_cookie = client.cookies["session"]
    async with app.state.sessionmaker() as db:
        stored = list(await db.scalars(select(VerificationToken)))
        sessions = list(await db.scalars(select(Session)))
    values = {t.otp_hash for t in stored} | {t.link_hash for t in stored}
    values |= {s.token_hash for s in sessions}
    assert code not in values and token not in values and session_cookie not in values
    assert all(len(v) == 64 for v in values)


def test_logout_cierra_la_sesion(client, mailer):
    login(client, mailer)
    old_cookie = client.cookies["session"]
    assert post(client, "/api/auth/logout").status_code == 204
    client.cookies.set("session", old_cookie)
    assert client.get("/api/me").status_code == 401


async def test_borrar_cuenta_elimina_usuario_y_sesiones(client, mailer, app):
    login(client, mailer)
    response = client.delete("/api/me", headers={"X-CSRF-Token": client.cookies["csrf_token"]})
    assert response.status_code == 204
    async with app.state.sessionmaker() as db:
        assert list(await db.scalars(select(User))) == []
        assert list(await db.scalars(select(Session))) == []
        assert list(await db.scalars(select(VerificationToken))) == []


def test_email_invalido_rechazado(client):
    assert _start(client, "no-es-un-email").status_code == 422


def test_campos_extra_rechazados(client):
    response = post(client, "/api/auth/start", json={"email": EMAIL, "otro": "x@example.com"})
    assert response.status_code == 422
