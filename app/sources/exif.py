import asyncio
import contextlib
from dataclasses import dataclass
from io import BytesIO
from typing import Any

from PIL import Image, UnidentifiedImageError
from PIL.ExifTags import GPS, IFD, Base

from app.identity.types import VerifiedIdentity
from app.sources.base import Category, Finding, Source, SourceError
from app.sources.image_strip import (
    MIME_TYPES,
    StripResult,
    UnsupportedImageError,
    strip_metadata,
)

UNSUPPORTED = "Formato no soportado o archivo dañado: subí una foto JPEG, PNG o WebP."


@dataclass(frozen=True, slots=True)
class PhotoPayload:
    filename: str
    data: bytes


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="ignore")
    return str(value).replace("\x00", "").strip()[:120]


def _read_exif(data: bytes) -> Image.Exif:
    try:
        with Image.open(BytesIO(data)) as image:
            return image.getexif()
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise SourceError(UNSUPPORTED) from exc


def _degrees(value: Any) -> float:
    degrees, minutes, seconds = (float(part) for part in value)
    return degrees + minutes / 60 + seconds / 3600


def _gps(exif: Image.Exif) -> dict[str, float] | None:
    gps = exif.get_ifd(IFD.GPSInfo)
    try:
        latitude = _degrees(gps[GPS.GPSLatitude])
        longitude = _degrees(gps[GPS.GPSLongitude])
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        return None
    if _text(gps.get(GPS.GPSLatitudeRef, "N")).upper() == "S":
        latitude = -latitude
    if _text(gps.get(GPS.GPSLongitudeRef, "E")).upper() == "W":
        longitude = -longitude
    result = {"latitude": round(latitude, 6), "longitude": round(longitude, 6)}
    with contextlib.suppress(KeyError, TypeError, ValueError, ZeroDivisionError):
        result["altitude_m"] = round(float(gps[GPS.GPSAltitude]), 1)
    return result


def _collect_tags(exif: Image.Exif, tags: dict[int, str]) -> dict[str, str]:
    sub_ifd = exif.get_ifd(IFD.Exif)
    found: dict[str, str] = {}
    for tag, label in tags.items():
        value = exif.get(tag) or sub_ifd.get(tag)
        text = _text(value) if value is not None else ""
        if text:
            found[label] = text
    return found


_IDENTIFIERS = {
    Base.BodySerialNumber: "Número de serie de la cámara",
    Base.LensSerialNumber: "Número de serie del lente",
    Base.CameraOwnerName: "Dueño de la cámara",
    Base.Artist: "Autor",
    Base.Copyright: "Copyright",
    Base.ImageUniqueID: "ID único de la imagen",
}
_DEVICE = {Base.Make: "Marca", Base.Model: "Modelo", Base.LensModel: "Lente"}
_DATES = {
    Base.DateTimeOriginal: "Fecha de la toma",
    Base.DateTimeDigitized: "Fecha de digitalización",
    Base.DateTime: "Fecha de modificación",
}
_SOFTWARE = {Base.Software: "Programa", Base.HostComputer: "Equipo"}


def _describe(values: dict[str, str]) -> str:
    return "; ".join(f"{label}: {value}" for label, value in values.items())


def analyze_photo(filename: str, data: bytes) -> list[Finding]:
    try:
        stripped = strip_metadata(data)
    except UnsupportedImageError as exc:
        raise SourceError(UNSUPPORTED) from exc
    exif = _read_exif(data)

    def finding(code: str, title: str, detail: str, extra: dict[str, Any]) -> Finding:
        return Finding(
            source=ExifSource.name,
            category=ExifSource.category,
            code=code,
            title=title,
            detail=detail,
            data={"photo": filename, **extra},
        )

    findings: list[Finding] = []
    if gps := _gps(exif):
        findings.append(
            finding(
                "exif.gps",
                "Ubicación GPS exacta",
                f"La foto guarda dónde se tomó: {gps['latitude']}, {gps['longitude']}.",
                gps,
            )
        )
    groups = (
        ("exif.identifiers", "Datos que te identifican o vinculan tus fotos", _IDENTIFIERS),
        ("exif.device", "Modelo del dispositivo", _DEVICE),
        ("exif.datetime", "Fecha y hora", _DATES),
        ("exif.software", "Programa o equipo usado", _SOFTWARE),
    )
    for code, title, tags in groups:
        values = _collect_tags(exif, tags)
        if code == "exif.datetime":
            # EXIF guarda "AAAA:MM:DD HH:MM:SS"; se muestra como fecha legible.
            values = {label: value.replace(":", "-", 2) for label, value in values.items()}
        if values:
            findings.append(finding(code, title, _describe(values), {"values": values}))
    others = sorted({label for label in stripped.removed if label != "EXIF"})
    if others:
        findings.append(
            finding(
                "exif.embedded_metadata",
                "Otros metadatos incrustados",
                "También contiene: " + ", ".join(others) + ".",
                {"blocks": others},
            )
        )
    if not findings:
        findings.append(finding("exif.clean", "Sin metadatos sensibles", "", {}))
    return findings


def clean_photo(data: bytes) -> tuple[StripResult, str]:
    try:
        orientation = _read_exif(data).get(Base.Orientation)
        result = strip_metadata(data, orientation if isinstance(orientation, int) else None)
    except UnsupportedImageError as exc:
        raise SourceError(UNSUPPORTED) from exc
    return result, MIME_TYPES[result.format]


class ExifSource(Source[PhotoPayload]):
    """Las fotos se procesan solo en memoria: nunca se escriben en disco ni se guardan."""

    name = "exif"
    category = Category.PHOTOS

    async def collect(self, identity: VerifiedIdentity, payload: PhotoPayload) -> list[Finding]:
        return await asyncio.to_thread(analyze_photo, payload.filename, payload.data)
