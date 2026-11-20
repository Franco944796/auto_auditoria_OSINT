# syntax=docker/dockerfile:1

# Etapa 1: minifica JS y CSS. En el servidor solo se publica la versión minificada.
FROM node:22-alpine AS assets
WORKDIR /build
RUN npm install --global esbuild@0.24.2
COPY app/web/static ./static
RUN esbuild static/js/*.js --minify --format=esm --outdir=static/js --allow-overwrite \
    && esbuild static/css/app.css --minify --outfile=static/css/app.css --allow-overwrite

# Etapa 2: imagen final. Se instala el paquete y se borra el código fuente suelto.
FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /srv
COPY pyproject.toml LICENSE ./
COPY app ./app
COPY --from=assets /build/static ./app/web/static
RUN pip install . \
    && rm -rf /srv/app /srv/pyproject.toml /srv/build \
    && useradd --create-home --uid 10001 appuser \
    && mkdir -p /srv/data \
    && chown appuser:appuser /srv/data
USER appuser
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')"]
# --proxy-headers: la IP real y el esquema https llegan desde Caddy (X-Forwarded-*).
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*", "--no-access-log"]
