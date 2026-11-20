import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import EmailStr, StringConstraints

from app.config import Settings
from app.deps import (
    SESSION_COOKIE,
    IdentityDep,
    LimiterDep,
    MailerDep,
    SettingsDep,
    VerificationDep,
    limit_ip,
)
from app.identity.mailer import verification_email
from app.identity.service import normalize_email
from app.identity.types import VerifiedIdentity
from app.schemas import StrictModel
from app.security.ratelimit import Limit, subject_key

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["identidad"])

GENERIC_START = "Si el email es válido, te enviamos un código y un enlace. Revisá tu bandeja."
INVALID = "El código o el enlace no es válido, venció o ya se usó. Pedí uno nuevo."


class StartRequest(StrictModel):
    email: EmailStr


class CodeRequest(StrictModel):
    email: EmailStr
    code: Annotated[str, StringConstraints(pattern=r"^\d{6}$")]


class LinkRequest(StrictModel):
    token: Annotated[str, StringConstraints(min_length=20, max_length=100)]


class MeResponse(StrictModel):
    email: str


def _set_session_cookie(response: Response, raw: str, settings: Settings) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        raw,
        max_age=settings.session_ttl_minutes * 60,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )


async def _open_session(
    identity: VerifiedIdentity | None,
    service: VerificationDep,
    response: Response,
    settings: Settings,
) -> MeResponse:
    if identity is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, INVALID)
    raw = await service.create_session(identity)
    _set_session_cookie(response, raw, settings)
    return MeResponse(email=identity.email)


@router.post(
    "/auth/start",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(limit_ip("auth_start", Limit(10, 600)))],
)
async def start_verification(
    body: StartRequest,
    service: VerificationDep,
    mailer: MailerDep,
    limiter: LimiterDep,
    settings: SettingsDep,
) -> dict[str, str]:
    email = normalize_email(body.email)
    await limiter.hit(f"auth_start:email:{subject_key(email)}", Limit(3, 900))
    issued = await service.start(email)
    # El token va en el fragmento (#): el navegador no lo manda al servidor ni queda en logs.
    link = f"{settings.public_base_url.rstrip('/')}/verificar#t={issued.link_token}"
    subject, text = verification_email(issued.otp, link, settings.verification_ttl_minutes)
    try:
        await mailer.send(email, subject, text)
    except Exception as exc:
        logger.exception("No se pudo enviar el email de verificación")
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "No pudimos enviar el email. Probá de nuevo en unos minutos.",
        ) from exc
    return {"detail": GENERIC_START}


@router.post("/auth/verify-code", dependencies=[Depends(limit_ip("auth_verify", Limit(20, 600)))])
async def verify_code(
    body: CodeRequest,
    service: VerificationDep,
    limiter: LimiterDep,
    response: Response,
    settings: SettingsDep,
) -> MeResponse:
    email = normalize_email(body.email)
    await limiter.hit(f"auth_verify:email:{subject_key(email)}", Limit(10, 900))
    identity = await service.verify_code(email, body.code)
    return await _open_session(identity, service, response, settings)


@router.post("/auth/verify-link", dependencies=[Depends(limit_ip("auth_verify", Limit(20, 600)))])
async def verify_link(
    body: LinkRequest, service: VerificationDep, response: Response, settings: SettingsDep
) -> MeResponse:
    identity = await service.verify_link(body.token)
    return await _open_session(identity, service, response, settings)


@router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, service: VerificationDep, response: Response) -> None:
    raw = request.cookies.get(SESSION_COOKIE)
    if raw:
        await service.end_session(raw)
    response.delete_cookie(SESSION_COOKIE, path="/")


@router.get("/session")
async def session_status(request: Request, service: VerificationDep) -> dict[str, bool]:
    """Para la portada: saber si hay sesión sin provocar un 401 en la consola."""
    raw = request.cookies.get(SESSION_COOKIE)
    return {"authenticated": bool(raw and await service.resolve_session(raw))}


@router.get("/me")
async def me(identity: IdentityDep) -> MeResponse:
    return MeResponse(email=identity.email)


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
async def delete_me(identity: IdentityDep, service: VerificationDep, response: Response) -> None:
    await service.delete_account(identity)
    response.delete_cookie(SESSION_COOKIE, path="/")
