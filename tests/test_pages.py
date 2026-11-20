import re
from pathlib import Path

import pytest

from app.web.pages import STATIC_DIR, WEB_DIR

PAGES = ["/", "/verificar", "/panel", "/privacidad"]


@pytest.mark.parametrize("path", PAGES)
def test_paginas_responden_con_csp(client, path):
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "script-src 'self'" in response.headers["content-security-policy"]
    assert '<html lang="es">' in response.text


def test_panel_y_verificar_no_se_indexan(client):
    for path in ("/panel", "/verificar"):
        assert 'content="noindex, nofollow"' in client.get(path).text


def test_estaticos_se_sirven(client):
    response = client.get("/static/js/panel.js")
    assert response.status_code == 200
    assert "javascript" in response.headers["content-type"]
    assert client.get("/static/css/app.css").status_code == 200


def test_sin_scripts_ni_estilos_inline_que_rompan_la_csp():
    for template in (WEB_DIR / "templates").glob("*.html"):
        html = template.read_text()
        assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html), template.name
        assert " style=" not in html and "<style" not in html, template.name
        assert not re.search(r"\son[a-z]+=", html), template.name


def test_js_nunca_envia_la_contrasena_al_backend():
    passwords = (STATIC_DIR / "js" / "passwords.js").read_text()
    assert "api.pwnedpasswords.com/range/" in passwords
    assert "hash.slice(0, 5)" in passwords
    panel = (STATIC_DIR / "js" / "panel.js").read_text()
    sent = re.search(r"state\.passwordChecks\.push\(\{(.*?)\}\)", panel, re.S)
    assert sent and "password" not in sent.group(1).replace("passwordChecks", "")


def test_csp_permite_solo_pwned_passwords_como_destino_externo():
    from app.security.middleware import CSP

    connect = next(part for part in CSP.split("; ") if part.startswith("connect-src"))
    assert connect == "connect-src 'self' https://api.pwnedpasswords.com"


def test_privacidad_explica_lo_que_no_se_guarda(client):
    text = client.get("/privacidad").text
    for expected in ("Qué NO guardamos", "Resultados del análisis", "Tus fotos", "Tus contraseñas"):
        assert expected in text


def test_plantillas_existen():
    assert {p.name for p in (WEB_DIR / "templates").glob("*.html")} >= {
        "base.html",
        "inicio.html",
        "verificar.html",
        "panel.html",
        "privacidad.html",
    }
    assert Path(STATIC_DIR / "css" / "app.css").exists()


def test_fuente_inter_se_sirve_localmente_con_su_licencia(client):
    response = client.get("/static/fonts/inter-latin.woff2")
    assert response.status_code == 200
    assert response.content[:4] == b"wOF2"
    assert (STATIC_DIR / "fonts" / "OFL.txt").exists()
    css = (STATIC_DIR / "css" / "app.css").read_text()
    assert "fonts.googleapis" not in css and "/static/fonts/inter-latin.woff2" in css
