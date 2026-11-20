"""Borrado de metadatos sin recomprimir: se recorre el contenedor (JPEG, PNG, WebP) y se
descartan los bloques de metadatos, así la foto limpia no pierde calidad."""

import zlib
from dataclasses import dataclass, field
from enum import StrEnum

from PIL import Image
from PIL.ExifTags import Base


class ImageFormat(StrEnum):
    JPEG = "jpeg"
    PNG = "png"
    WEBP = "webp"


MIME_TYPES = {
    ImageFormat.JPEG: "image/jpeg",
    ImageFormat.PNG: "image/png",
    ImageFormat.WEBP: "image/webp",
}
EXTENSIONS = {ImageFormat.JPEG: "jpg", ImageFormat.PNG: "png", ImageFormat.WEBP: "webp"}

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
TRAILING = "datos ocultos tras el fin de la imagen"


class UnsupportedImageError(ValueError):
    pass


@dataclass
class StripResult:
    format: ImageFormat
    data: bytes
    removed: list[str] = field(default_factory=list)


def detect_format(data: bytes) -> ImageFormat:
    if data.startswith(b"\xff\xd8\xff"):
        return ImageFormat.JPEG
    if data.startswith(PNG_SIGNATURE):
        return ImageFormat.PNG
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ImageFormat.WEBP
    raise UnsupportedImageError("formato no soportado")


def strip_metadata(data: bytes, orientation: int | None = None) -> StripResult:
    """Sin el tag Orientation algunas fotos se verían giradas: si se pasa, se conserva solo ese."""
    image_format = detect_format(data)
    keep_orientation = orientation if orientation in range(2, 9) else None
    stripper = {
        ImageFormat.JPEG: _strip_jpeg,
        ImageFormat.PNG: _strip_png,
        ImageFormat.WEBP: _strip_webp,
    }[image_format]
    try:
        cleaned, removed = stripper(data, keep_orientation)
    except IndexError as exc:
        raise UnsupportedImageError("imagen dañada") from exc
    return StripResult(image_format, cleaned, removed)


def _orientation_tiff(orientation: int) -> bytes:
    exif = Image.Exif()
    exif[Base.Orientation] = orientation
    return exif.tobytes()[len(b"Exif\x00\x00") :]


_JPEG_KEEP = {0xE0: b"JFIF\x00", 0xE2: b"ICC_PROFILE\x00", 0xEE: b"Adobe"}


def _jpeg_is_metadata(marker: int, payload: bytes) -> bool:
    if marker == 0xFE:
        return True
    if 0xE0 <= marker <= 0xEF:
        prefix = _JPEG_KEEP.get(marker)
        return prefix is None or not payload.startswith(prefix)
    return False


def _jpeg_label(marker: int, payload: bytes) -> str:
    if marker == 0xE1 and payload.startswith(b"Exif"):
        return "EXIF"
    if marker == 0xE1 and payload.startswith(b"http://ns.adobe.com/xap/"):
        return "XMP"
    if marker == 0xED:
        return "IPTC/Photoshop"
    if marker == 0xFE:
        return "comentario"
    if marker == 0xE2 and payload.startswith(b"MPF"):
        return "imágenes secundarias (MPF)"
    if marker == 0xE0:
        return "miniatura (JFXX)"
    return f"APP{marker - 0xE0}"


def _jpeg_scan_end(data: bytes, start: int) -> int:
    # En los datos comprimidos un 0xFF real va seguido de 0x00 o es un RSTn; cualquier otro
    # marcador indica el fin del scan (en JPEG progresivos vienen más segmentos después).
    position = start
    while True:
        position = data.find(b"\xff", position)
        if position == -1 or position + 1 >= len(data):
            return len(data)
        following = data[position + 1]
        if following == 0xFF:
            position += 1
        elif following == 0x00 or 0xD0 <= following <= 0xD7:
            position += 2
        else:
            return position


def _strip_jpeg(data: bytes, orientation: int | None) -> tuple[bytes, list[str]]:
    kept: list[bytes] = []
    removed: list[str] = []
    position, size = 2, len(data)
    while position < size:
        if data[position] != 0xFF:
            raise UnsupportedImageError("JPEG dañado")
        marker = data[position + 1]
        if marker == 0xFF:
            position += 1
            continue
        if marker == 0xD9:
            kept.append(b"\xff\xd9")
            position += 2
            break
        if 0xD0 <= marker <= 0xD7 or marker == 0x01:
            kept.append(data[position : position + 2])
            position += 2
            continue
        length = int.from_bytes(data[position + 2 : position + 4], "big")
        end = position + 2 + length
        if length < 2 or end > size:
            raise UnsupportedImageError("JPEG dañado")
        if marker == 0xDA:
            scan_end = _jpeg_scan_end(data, end)
            kept.append(data[position:scan_end])
            position = scan_end
            continue
        payload = data[position + 4 : end]
        if _jpeg_is_metadata(marker, payload):
            removed.append(_jpeg_label(marker, payload))
        else:
            kept.append(data[position:end])
        position = end
    if position < size:
        removed.append(TRAILING)
    if orientation is not None:
        payload = b"Exif\x00\x00" + _orientation_tiff(orientation)
        segment = b"\xff\xe1" + (len(payload) + 2).to_bytes(2, "big") + payload
        insert_at = 1 if kept and kept[0][:2] == b"\xff\xe0" else 0
        kept.insert(insert_at, segment)
    return b"\xff\xd8" + b"".join(kept), removed


_PNG_METADATA = {
    b"eXIf": "EXIF",
    b"tEXt": "texto incrustado",
    b"zTXt": "texto incrustado",
    b"iTXt": "texto incrustado o XMP",
    b"tIME": "fecha de modificación",
}


def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + payload).to_bytes(4, "big")
    return len(payload).to_bytes(4, "big") + chunk_type + payload + crc


def _strip_png(data: bytes, orientation: int | None) -> tuple[bytes, list[str]]:
    kept = [PNG_SIGNATURE]
    removed: list[str] = []
    position, size = len(PNG_SIGNATURE), len(data)
    pending_exif = orientation
    while position + 8 <= size:
        length = int.from_bytes(data[position : position + 4], "big")
        chunk_type = data[position + 4 : position + 8]
        end = position + 12 + length
        if end > size:
            raise UnsupportedImageError("PNG dañado")
        if chunk_type in _PNG_METADATA:
            removed.append(_PNG_METADATA[chunk_type])
        else:
            if chunk_type == b"IDAT" and pending_exif is not None:
                kept.append(_png_chunk(b"eXIf", _orientation_tiff(pending_exif)))
                pending_exif = None
            kept.append(data[position:end])
        position = end
        if chunk_type == b"IEND":
            break
    if position < size:
        removed.append(TRAILING)
    return b"".join(kept), removed


_VP8X_EXIF_FLAG = 0x08
_VP8X_XMP_FLAG = 0x04


def _strip_webp(data: bytes, orientation: int | None) -> tuple[bytes, list[str]]:
    chunks: list[bytearray] = []
    removed: list[str] = []
    riff_end = min(8 + int.from_bytes(data[4:8], "little"), len(data))
    position = 12
    while position + 8 <= riff_end:
        fourcc = data[position : position + 4]
        length = int.from_bytes(data[position + 4 : position + 8], "little")
        end = position + 8 + length + (length & 1)
        if position + 8 + length > len(data):
            raise UnsupportedImageError("WebP dañado")
        if fourcc == b"EXIF":
            removed.append("EXIF")
        elif fourcc == b"XMP ":
            removed.append("XMP")
        else:
            chunks.append(bytearray(data[position:end]))
        position = end
    if riff_end < len(data):
        removed.append(TRAILING)

    extended = next((chunk for chunk in chunks if chunk[:4] == b"VP8X"), None)
    if extended is not None:
        extended[8] &= ~(_VP8X_EXIF_FLAG | _VP8X_XMP_FLAG) & 0xFF
        # El formato WebP simple (sin VP8X) no admite EXIF: ahí no hay orientación que conservar.
        if orientation is not None:
            extended[8] |= _VP8X_EXIF_FLAG
            tiff = _orientation_tiff(orientation)
            padding = b"\x00" if len(tiff) & 1 else b""
            chunks.append(bytearray(b"EXIF" + len(tiff).to_bytes(4, "little") + tiff + padding))
    body = b"WEBP" + b"".join(chunks)
    return b"RIFF" + len(body).to_bytes(4, "little") + body, removed
