import logging
from email.message import EmailMessage
from typing import Protocol

import aiosmtplib

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


class ConsoleMailer:
    """Solo desarrollo: deja el código en el log en lugar de enviarlo."""

    async def send(self, to: str, subject: str, body: str) -> None:
        logger.warning("Email de desarrollo (no enviado)\nAsunto: %s\n\n%s", subject, body)


def build_mailer(settings: Settings) -> Mailer:
    if settings.mail_backend == "console":
        if settings.environment == "production":
            raise RuntimeError("MAIL_BACKEND=console no está permitido en producción")
        return ConsoleMailer()
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
