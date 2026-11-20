import tempfile

import pytest
from PIL.ExifTags import IFD, Base

from app.sources.exif import analyze_photo, clean_photo
from app.sources.image_strip import TRAILING, strip_metadata
from tests.conftest import csrf, login
from tests.images import (
    exif_of,
    jpeg_with_metadata,
    pixels,
    png_with_metadata,
    webp_with_metadata,
)


def _codes(findings):
    return {f.code: f for f in findings}


def test_detecta_gps_dispositivo_fecha_e_identificadores_en_jpeg():
    findings = _codes(analyze_photo("casa.jpg", jpeg_with_metadata()))
    gps = findings["exif.gps"]
    assert gps.data["latitude"] == pytest.approx(-34.603333, abs=1e-5)
    assert gps.data["longitude"] == pytest.approx(-58.38, abs=1e-5)
    assert "-34.603333" in gps.detail
    assert gps.data["photo"] == "casa.jpg"
    assert findings["exif.device"].data["values"] == {"Marca": "Apple", "Modelo": "iPhone 15"}
    assert "2026-01-02 10:00:00" in findings["exif.datetime"].detail
    assert "SN123456" in findings["exif.identifiers"].detail
    assert "17.1" in findings["exif.software"].detail
    assert set(findings["exif.embedded_metadata"].data["blocks"]) == {"XMP", "comentario"}


def test_jpeg_limpio_sin_metadatos_y_sin_perdida():
    original = jpeg_with_metadata()
    result, mime = clean_photo(original)
    assert mime == "image/jpeg"
    assert set(result.removed) >= {"EXIF", "XMP", "comentario"}
    exif = exif_of(result.data)
    assert dict(exif) == {Base.Orientation: 6}
    assert exif.get_ifd(IFD.GPSInfo) == {}
    assert b"secreto" not in result.data and b"mi casa" not in result.data
    assert pixels(result.data) == pixels(original)
    assert {f.code for f in analyze_photo("x.jpg", result.data)} == {"exif.clean"}


def test_jpeg_progresivo_se_limpia_sin_perdida():
    original = jpeg_with_metadata(progressive=True)
    result, _ = clean_photo(original)
    assert pixels(result.data) == pixels(original)
    assert exif_of(result.data).get_ifd(IFD.GPSInfo) == {}


def test_datos_ocultos_tras_el_fin_de_la_imagen_se_eliminan():
    original = jpeg_with_metadata() + b"Exif\x00\x00datos-escondidos"
    result = strip_metadata(original)
    assert TRAILING in result.removed
    assert b"datos-escondidos" not in result.data
    assert result.data.endswith(b"\xff\xd9")


def test_png_limpio():
    original = png_with_metadata()
    findings = _codes(analyze_photo("p.png", original))
    assert "exif.gps" in findings
    assert "texto incrustado" in findings["exif.embedded_metadata"].data["blocks"]
    result, mime = clean_photo(original)
    assert mime == "image/png"
    assert b"eXIf" not in result.data and b"tEXt" not in result.data
    assert b"Yo Mismo" not in result.data
    assert pixels(result.data) == pixels(original)


def test_webp_limpio():
    original = webp_with_metadata()
    assert "exif.gps" in _codes(analyze_photo("w.webp", original))
    result, mime = clean_photo(original)
    assert mime == "image/webp"
    assert b"EXIF" not in result.data
    assert dict(exif_of(result.data)) == {}
    assert pixels(result.data) == pixels(original)


def test_foto_sin_metadatos_informa_limpia():
    clean, _ = clean_photo(png_with_metadata())
    assert [f.code for f in analyze_photo("x.png", clean.data)] == ["exif.clean"]


def _upload(client, path, data, name="mi foto.jpg"):
    headers = {**csrf(client), "Content-Type": "application/octet-stream", "X-Filename": name}
    return client.post(path, content=data, headers=headers)


def test_endpoint_analiza_y_limpia(client, mailer):
    login(client, mailer)
    analysis = _upload(client, "/api/photos/analyze", jpeg_with_metadata())
    assert analysis.status_code == 200
    body = analysis.json()
    assert body["photo"] == "mi foto.jpg"
    assert "exif.gps" in {f["code"] for f in body["findings"]}

    cleaned = _upload(client, "/api/photos/clean", jpeg_with_metadata())
    assert cleaned.status_code == 200
    assert cleaned.headers["content-type"] == "image/jpeg"
    disposition = cleaned.headers["content-disposition"]
    assert disposition.startswith("attachment;") and "mi%20foto-sin-metadatos.jpg" in disposition
    assert exif_of(cleaned.content).get_ifd(IFD.GPSInfo) == {}


def test_nombre_de_archivo_saneado(client, mailer):
    login(client, mailer)
    body = _upload(client, "/api/photos/analyze", jpeg_with_metadata(), "../../etc/<x>.jpg").json()
    assert body["photo"] == "_x_.jpg"


def test_fotos_requieren_email_verificado(client):
    assert _upload(client, "/api/photos/analyze", jpeg_with_metadata()).status_code == 401
    assert _upload(client, "/api/photos/clean", jpeg_with_metadata()).status_code == 401


def test_formato_no_soportado(client, mailer):
    login(client, mailer)
    response = _upload(client, "/api/photos/analyze", b"GIF89a" + b"\x00" * 50)
    assert response.status_code == 415
    assert "JPEG, PNG o WebP" in response.json()["detail"]


def test_foto_demasiado_grande(client, mailer, settings):
    settings.max_upload_bytes = 1000
    login(client, mailer)
    assert (
        _upload(client, "/api/photos/analyze", jpeg_with_metadata() + b"0" * 2000).status_code
        == 413
    )


def test_las_fotos_nunca_tocan_el_disco(client, mailer, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("se intentó crear un archivo temporal")

    for name in ("SpooledTemporaryFile", "TemporaryFile", "NamedTemporaryFile", "mkstemp"):
        monkeypatch.setattr(tempfile, name, forbidden)
    login(client, mailer)
    big = jpeg_with_metadata() + b"\x00" * (3 * 1024 * 1024)
    assert _upload(client, "/api/photos/analyze", big).status_code == 200
    assert _upload(client, "/api/photos/clean", big).status_code == 200
