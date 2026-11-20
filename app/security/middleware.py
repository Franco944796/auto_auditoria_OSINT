import secrets

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.base import RequestResponseEndpoint

from app.config import Settings
from app.security.ratelimit import Limit, RateLimiter, RateLimitExceeded, subject_key

CSRF_COOKIE = "csrf_token"
CSRF_HEADER = "x-csrf-token"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
EXEMPT_PATHS = {"/healthz"}

# El chequeo de contraseñas va directo del navegador a Pwned Passwords (ver static/js/passwords.js).
CSP = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data: blob:",
        "connect-src 'self' https://api.pwnedpasswords.com",
        "font-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ]
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    # no-referrer evita que el token del magic link se filtre a otro sitio por el Referer.
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def _error(status_code: int, detail: str, headers: dict[str, str] | None = None) -> Response:
    return JSONResponse({"detail": detail}, status_code=status_code, headers=headers)


def install_security_middleware(app: FastAPI, settings: Settings) -> None:
    """El último middleware registrado es el más externo: HTTPS → cabeceras → límite → CSRF."""

    @app.middleware("http")
    async def csrf_protection(request: Request, call_next: RequestResponseEndpoint) -> Response:
        cookie = request.cookies.get(CSRF_COOKIE)
        if request.method in UNSAFE_METHODS:
            origin = request.headers.get("origin")
            expected = f"{request.url.scheme}://{request.headers.get('host', '')}"
            if origin is not None and origin != expected:
                return _error(403, "Origen no permitido.")
            header = request.headers.get(CSRF_HEADER)
            if not cookie or not header or not secrets.compare_digest(cookie, header):
                return _error(403, "Falta el token de seguridad (CSRF). Recargá la página.")
        response = await call_next(request)
        if not cookie:
            response.set_cookie(
                CSRF_COOKIE,
                secrets.token_urlsafe(32),
                secure=settings.cookie_secure,
                samesite="strict",
                httponly=False,
                path="/",
            )
        return response

    global_limit = Limit(settings.rate_limit_global_per_minute, 60)

    @app.middleware("http")
    async def global_rate_limit(request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path not in EXEMPT_PATHS:
            host = request.client.host if request.client else "desconocida"
            try:
                await RateLimiter(request.app.state.redis).hit(
                    f"global:ip:{subject_key(host)}", global_limit
                )
            except RateLimitExceeded as exc:
                return rate_limited_response(exc)
        return await call_next(request)

    @app.middleware("http")
    async def security_headers(request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    if settings.force_https:

        @app.middleware("http")
        async def https_redirect(request: Request, call_next: RequestResponseEndpoint) -> Response:
            if request.url.scheme == "http" and request.url.path not in EXEMPT_PATHS:
                return RedirectResponse(str(request.url.replace(scheme="https")), 308)
            return await call_next(request)


def rate_limited_response(exc: RateLimitExceeded) -> Response:
    return _error(
        429,
        "Demasiadas solicitudes. Esperá un momento y volvé a intentar.",
        {"Retry-After": str(exc.retry_after)},
    )
