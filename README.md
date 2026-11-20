# Autoauditoría de exposición digital

Aplicación web para que una persona revise qué información **sobre ella misma** está expuesta en
internet y reciba un plan concreto para reducirla:

- **Filtraciones de datos** de su email verificado (Have I Been Pwned v3).
- **Contraseñas comprometidas** con k-anonimidad (Pwned Passwords), calculadas en el navegador.
- **Metadatos de sus fotos** (GPS, dispositivo, fechas, números de serie) y descarga de una copia limpia.
- **Informe** con riesgo bajo / medio / alto por categoría y pasos de remediación.

> Principio no negociable: solo datos propios y verificados. No existe búsqueda libre por nombre,
> usuario, teléfono ni email de otra persona. Toda fuente recibe el sujeto desde la sesión verificada.

Software propietario: ver [LICENSE](LICENSE).

## Requisitos

- Docker y Docker Compose (camino recomendado), o
- Python 3.12+ y un Redis 7 para desarrollo sin contenedores.

## Configuración

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # pegar en SECRET_KEY
```

### API key de Have I Been Pwned

1. Comprar una suscripción en <https://haveibeenpwned.com/API/Key>.
2. Ponerla en `HIBP_API_KEY` del `.env`.
3. Ajustar `HIBP_REQUESTS_PER_MINUTE` al límite del plan contratado: los workers se reparten ese
   cupo entre todos a través de Redis.

Sin API key la app funciona, pero el análisis de filtraciones responde que no está configurado.
Pwned Passwords no necesita clave.

Variables principales (todas en [.env.example](.env.example)):

| Variable | Para qué |
|---|---|
| `SECRET_KEY` | HMAC de códigos, enlaces y sesiones (mínimo 32 caracteres) |
| `PUBLIC_BASE_URL` | URL pública con la que se arman los magic links |
| `MAIL_BACKEND` | `smtp` o `console` (este último solo en desarrollo) |
| `SMTP_*`, `MAIL_FROM` | Servidor de correo para los códigos |
| `FORCE_HTTPS`, `COOKIE_SECURE` | En `false` solo para desarrollo sin TLS |
| `RESULT_TTL_SECONDS` | Vida de los resultados efímeros en Redis (10 min por defecto) |

## Ejecución con Docker

```bash
docker compose --profile dev up --build
```

- App: <https://localhost:8443>. Caddy usa una CA local: el navegador va a advertir del
  certificado hasta que confíes en ella (`docker compose exec caddy caddy trust` o aceptando la
  advertencia).
- Bandeja de Mailpit, con los códigos de verificación: <http://localhost:8025>.

El perfil `dev` agrega Mailpit. En producción se levanta sin el perfil y con un SMTP real.

## Ejecución local sin Docker

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"
redis-server --save "" --appendonly no &        # o un Redis existente
export MAIL_BACKEND=console FORCE_HTTPS=false COOKIE_SECURE=false \
       PUBLIC_BASE_URL=http://localhost:8000 REDIS_URL=redis://localhost:6379/0
.venv/bin/uvicorn app.main:create_app --factory --reload &
.venv/bin/arq app.jobs.worker.WorkerSettings
```

Abrir <http://localhost:8000> (no `127.0.0.1` con otro puerto: el chequeo de contraseñas usa
`crypto.subtle`, que exige HTTPS o `localhost`). El código de verificación aparece en el log.

## Tests y lint

```bash
.venv/bin/pytest -q
.venv/bin/ruff check . && .venv/bin/ruff format --check .
```

Las APIs externas se simulan con `respx` y Redis con `fakeredis`, así que los tests no necesitan
red ni servicios. [tests/test_unverified_cannot_analyze.py](tests/test_unverified_cannot_analyze.py)
comprueba que no se puede lanzar un análisis sobre un email no verificado.

## Arquitectura

```
verificación de identidad  →  recolección  →  análisis de riesgo  →  informe
      app/identity/             app/sources/       app/analysis/        app/report/
                                app/jobs/ (arq)
```

| Módulo | Responsabilidad |
|---|---|
| `app/identity/` | OTP + magic link, sesiones, envío de email. Único lugar que crea un `VerifiedIdentity`. |
| `app/sources/` | Una fuente por archivo con la interfaz común `Source.collect(identity, payload)`. Solo observan hechos (`Finding`). |
| `app/jobs/` | Cola arq para fuentes lentas; resultados en Redis con vencimiento (`ResultStore`). |
| `app/analysis/` | Reglas por código de hallazgo: severidad + pasos de remediación. Nivel por categoría y global. |
| `app/report/` | Arma el informe en memoria. No hay tabla de informes. |
| `app/security/` | Cabeceras (CSP, HSTS…), CSRF, rate limiting en Redis, redirección a HTTPS. |
| `app/api/` | Endpoints de análisis, fotos e informe. |
| `app/web/` | Plantillas Jinja y JS sin framework (sin paso de build en desarrollo). |

### Flujo

1. `POST /api/auth/start` envía un código de 6 dígitos y un enlace `…/verificar#t=…`. Ambos
   vencen a los 15 minutos, sirven una vez y se guardan como HMAC. El token va en el fragmento
   `#`, así no llega al servidor ni a los logs, y la página pide confirmar con un botón: los
   escáneres de correo abren enlaces pero no los consumen.
2. Con la sesión verificada, `POST /api/analysis/hibp` encola el trabajo; el navegador consulta
   `GET /api/analysis/jobs/{id}` hasta que termina.
3. Las contraseñas se comprueban desde el navegador directo contra `api.pwnedpasswords.com`, con
   la cabecera `Add-Padding`. Al backend solo llega cuántas veces apareció cada una.
4. Las fotos se envían como cuerpo crudo y se procesan en memoria. No se usa `UploadFile`,
   porque Starlette lo vuelca a disco por encima de 1 MB. La limpieza recorre el contenedor
   JPEG, PNG o WebP y descarta los bloques de metadatos sin recomprimir; solo conserva la
   orientación.
5. `POST /api/report` junta los hallazgos, aplica las reglas y devuelve el informe. El navegador lo
   muestra, lo descarga como HTML autocontenido o lo imprime a PDF.

### Agregar una fuente

1. Crear `app/sources/<nombre>.py` con una subclase de `Source[Payload]`:
   - definir `name` y `category`;
   - poner `runs_in_background = True` si consulta un servicio lento;
   - implementar `collect`, que recibe siempre un `VerifiedIdentity`.
2. Registrarla en `SOURCE_CLASSES` de [app/sources/registry.py](app/sources/registry.py).
   - Si corre en segundo plano, agregarla también a `build_background_sources`.
   - El endpoint `POST /api/analysis/{nombre}` la toma sin más cambios.
3. Agregar las reglas de sus códigos en [app/analysis/rules.py](app/analysis/rules.py) y, si es
   una categoría nueva, su resumen en [app/analysis/risk.py](app/analysis/risk.py).

Previstas fuera del MVP:

- **Cuentas vinculadas por OAuth:** una fuente cuyo payload es el token que concede el propio
  usuario.
- **Data brokers:** una lista curada de enlaces de opt-out, versionada en el repo y sin scraping.

### Seguridad y privacidad

- SQLite guarda solo usuarios, tokens de verificación (hash) y sesiones (hash).
- Los resultados de análisis viven en Redis con vencimiento. Redis corre sin RDB ni AOF.
- Rate limiting por IP en todo endpoint y, además, por cuenta o email en los sensibles.
- CSRF con doble envío (cookie `SameSite=Strict` + cabecera) y verificación de `Origin`.
- CSP sin `unsafe-inline`, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, HSTS.
- Los modelos de entrada rechazan campos extra: ningún endpoint acepta un email o sujeto ajeno.
- Contenedores de solo lectura, sin capacidades y con usuario no root. Uvicorn corre sin access log.
- En la imagen de producción, el JS y el CSS van minificados y no se incluye el código fuente suelto.
- `/docs` deshabilitado y `/openapi.json` solo en `development`.

## Antes de producción

- Dominio real en el `Caddyfile` (quitar `local_certs`) y en `PUBLIC_BASE_URL`.
- SMTP transaccional con SPF, DKIM y DMARC; sin el perfil `dev`.
- Completar el contacto en la página de privacidad y en `LICENSE`.
- Migraciones con Alembic si cambia el esquema. Hoy las tablas se crean al arrancar.
- Pasar a PostgreSQL si se usan varias réplicas de la app.
- Monitoreo de errores sin datos personales y copias de seguridad del volumen `appdata`.
- Revisión legal de la página de privacidad para la jurisdicción donde se ofrezca.
