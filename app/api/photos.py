import asyncio
import re
from pathlib import PurePosixPath
from typing import Annotated
from urllib.parse import quote, unquote

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from app.deps import SettingsDep, limit_account, limit_ip
from app.identity.types import VerifiedIdentity
from app.schemas import StrictModel
from app.security.ratelimit import Limit
from app.sources.base import Finding, SourceError
from app.sources.exif import ExifSource, PhotoPayload, clean_photo
from app.sources.image_strip import EXTENSIONS

router = APIRouter(prefix="/api/photos", tags=["recolección"])

exif_source = ExifSource()

PhotoIdentity = Annotated[VerifiedIdentity, Depends(limit_account("photos", Limit(200, 3600)))]
_UNSAFE_CHARS = re.compile(r"[^\w.\- ]+")


class PhotoAnalysis(StrictModel):
    photo: str
    findings: list[Finding]


async def read_body_in_memory(request: Request, max_bytes: int) -> bytes:
    """El cuerpo crudo se lee a memoria a propósito: UploadFile de Starlette vuelca a un archivo
    temporal en disco por encima de 1 MB, y las fotos no deben tocar el disco."""
    too_large = HTTPException(
        status.HTTP_413_CONTENT_TOO_LARGE,
        f"La foto supera el máximo de {max_bytes // (1024 * 1024)} MB.",
    )
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > max_bytes:
        raise too_large
    buffer = bytearray()
    async for chunk in request.stream():
        buffer += chunk
        if len(buffer) > max_bytes:
            raise too_large
    if not buffer:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No se recibió ninguna foto.")
    return bytes(buffer)


def photo_name(request: Request) -> str:
    raw = unquote(request.headers.get("x-filename", ""))
    name = _UNSAFE_CHARS.sub("_", PurePosixPath(raw.replace("\\", "/")).name).strip()
    return name[-80:] or "foto"


@router.post("/analyze", dependencies=[Depends(limit_ip("photos", Limit(400, 3600)))])
async def analyze(
    request: Request, identity: PhotoIdentity, settings: SettingsDep
) -> PhotoAnalysis:
    data = await read_body_in_memory(request, settings.max_upload_bytes)
    name = photo_name(request)
    try:
        findings = await exif_source.collect(identity, PhotoPayload(name, data))
    except SourceError as exc:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, str(exc)) from exc
    return PhotoAnalysis(photo=name, findings=findings)


@router.post("/clean", dependencies=[Depends(limit_ip("photos", Limit(400, 3600)))])
async def clean(request: Request, identity: PhotoIdentity, settings: SettingsDep) -> Response:
    data = await read_body_in_memory(request, settings.max_upload_bytes)
    try:
        result, mime = await asyncio.to_thread(clean_photo, data)
    except SourceError as exc:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, str(exc)) from exc
    stem = PurePosixPath(photo_name(request)).stem or "foto"
    filename = f"{stem}-sin-metadatos.{EXTENSIONS[result.format]}"
    return Response(
        content=result.data,
        media_type=mime,
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}",
            "Cache-Control": "no-store",
        },
    )
