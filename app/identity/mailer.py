import logging
from email.message import EmailMessage
from email.utils import parseaddr
from typing import Protocol

import aiosmtplib
import httpx

from app.config import Settings

logger = logging.getLogger(__name__)


class Mailer(Protocol):
    async def send(self, to: str, subject: str, body: str) -> None: ...


class SmtpMailer:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def send(self, to: str, subject: str, body: str) -> None:
        message = EmailMessage()
        message["From"] = self.settings.mail_from
        message["To"] = to
        message["Subject"] = subject
        message.set_content(body)
        password = self.settings.smtp_password.get_secret_value()
        await aiosmtplib.send(
            message,
            hostname=self.settings.smtp_host,
            port=self.settings.smtp_port,
            username=self.settings.smtp_username or None,
            password=password or None,
            start_tls=self.settings.smtp_starttls,
            use_tls=self.settings.smtp_use_tls,
        )


class BrevoMailer:
    """Envío por la API HTTPS de Brevo: sirve donde el hosting bloquea los puertos SMTP."""

    API_URL = "https://api.brevo.com/v3/smtp/email"

    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None) -> None:
        self.api_key = settings.brevo_api_key.get_secret_value()
        name, address = parseaddr(settings.mail_from)
        self.sender = {"name": name, "email": address} if name else {"email": address}
        self.client = client

    async def send(self, to: str, subject: str, body: str) -> None:
        if not self.api_key:
            raise RuntimeError("Falta BREVO_API_KEY")
        payload = {
            "sender": self.sender,
            "to": [{"email": to}],
            "subject": subject,
            "textContent": body,
        }
        headers = {"api-key": self.api_key, "accept": "application/json"}
        if self.client is not None:
            response = await self.client.post(self.API_URL, json=payload, headers=headers)
        else:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.post(self.API_URL, json=payload, headers=headers)
        if response.status_code not in (200, 201, 202):
            # Brevo devuelve {"code", "message"}; el cuerpo no incluye datos del destinatario.
            raise RuntimeError(f"Brevo respondió {response.status_code}: {response.text[:200]}")


class ConsoleMailer:
    """Solo desarrollo: deja el código en el log en lugar de enviarlo."""

    async def send(self, to: str, subject: str, body: str) -> None:
        logger.warning("Email de desarrollo (no enviado)\nAsunto: %s\n\n%s", subject, body)


def build_mailer(settings: Settings) -> Mailer:
    if settings.mail_backend == "console":
        if settings.environment == "production":
            raise RuntimeError("MAIL_BACKEND=console no está permitido en producción")
        return ConsoleMailer()
    if settings.mail_backend == "brevo":
        return BrevoMailer(settings)
    return SmtpMailer(settings)


def verification_email(otp: str, link: str, ttl_minutes: int) -> tuple[str, str]:
    subject = f"Tu código de verificación: {otp}"
    body = (
        "Alguien (probablemente vos) pidió revisar la exposición digital de este email.\n\n"
        f"Código: {otp}\n\n"
        f"O abrí este enlace y confirmá: {link}\n\n"
        f"El código y el enlace vencen en {ttl_minutes} minutos y sirven una sola vez.\n"
        "Si no fuiste vos, ignorá este mensaje: sin el código nadie puede analizar tu email."
    )
    return subject, body
