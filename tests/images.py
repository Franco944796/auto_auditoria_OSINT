from io import BytesIO

from PIL import Image, PngImagePlugin
from PIL.ExifTags import GPS, IFD, Base

XMP = b"http://ns.adobe.com/xap/1.0/\x00<x:xmpmeta><rdf:RDF>secreto</rdf:RDF></x:xmpmeta>"


def sample_exif(orientation: int = 6, gps: bool = True) -> Image.Exif:
    exif = Image.Exif()
    exif[Base.Make] = "Apple"
    exif[Base.Model] = "iPhone 15"
    exif[Base.Software] = "17.1"
    exif[Base.Orientation] = orientation
    sub = exif.get_ifd(IFD.Exif)
    sub[Base.DateTimeOriginal] = "2026:01:02 10:00:00"
    sub[Base.BodySerialNumber] = "SN123456"
    if gps:
        location = exif.get_ifd(IFD.GPSInfo)
        location[GPS.GPSLatitudeRef] = "S"
        location[GPS.GPSLatitude] = (34.0, 36.0, 12.0)
        location[GPS.GPSLongitudeRef] = "W"
        location[GPS.GPSLongitude] = (58.0, 22.0, 48.0)
    return exif


def _picture() -> Image.Image:
    image = Image.new("RGB", (64, 48), "white")
    for x in range(64):
        image.putpixel((x, x % 48), (x * 4, 0, 255 - x * 4))
    return image


def insert_jpeg_segment(data: bytes, marker: int, payload: bytes) -> bytes:
    segment = bytes([0xFF, marker]) + (len(payload) + 2).to_bytes(2, "big") + payload
    return data[:2] + segment + data[2:]


def jpeg_with_metadata(**save_options) -> bytes:
    buffer = BytesIO()
    _picture().save(buffer, "JPEG", exif=sample_exif(), comment=b"foto de mi casa", **save_options)
    return insert_jpeg_segment(buffer.getvalue(), 0xE1, XMP)


def png_with_metadata() -> bytes:
    info = PngImagePlugin.PngInfo()
    info.add_text("Author", "Yo Mismo")
    buffer = BytesIO()
    _picture().save(buffer, "PNG", exif=sample_exif(orientation=1), pnginfo=info)
    return buffer.getvalue()


def webp_with_metadata() -> bytes:
    buffer = BytesIO()
    _picture().save(buffer, "WEBP", exif=sample_exif(orientation=1), lossless=True)
    return buffer.getvalue()


def pixels(data: bytes) -> bytes:
    with Image.open(BytesIO(data)) as image:
        return image.convert("RGB").tobytes()


def exif_of(data: bytes) -> Image.Exif:
    with Image.open(BytesIO(data)) as image:
        return image.getexif()
