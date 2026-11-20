# Autoauditoría de exposición digital

Aplicación web para que una persona revise qué información **sobre ella misma** está expuesta en
internet y reciba un plan concreto para reducirla:

- **Filtraciones de datos** de su email verificado: Have I Been Pwned v3 si hay API key, o
  XposedOrNot (gratis) si no.
- **Contraseñas comprometidas** con k-anonimidad (Pwned Passwords), calculadas en el navegador.
- **Metadatos de sus fotos** (GPS, dispositivo, fechas, números de serie) y descarga de una copia limpia.
- **Informe** con riesgo bajo / medio / alto por categoría y pasos de remediación.

> Principio no negociable: solo datos propios y verificados. No existe búsqueda libre por nombre,
> usuario, teléfono ni email de otra persona. Toda fuente recibe el sujeto desde la sesión verificada.

El código es visible pero no libre: se puede leer y estudiar, no usar, desplegar ni copiar sin
permiso. Ver [LICENSE](LICENSE).

## Tests

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
| `app/jobs/` | Fuentes lentas en segundo plano: arq (worker aparte) o tareas dentro de la app (`JOB_BACKEND=inprocess`). Resultados en Redis con vencimiento (`ResultStore`). |
| `app/analysis/` | Reglas por código de hallazgo: severidad + pasos de remediación. Nivel por categoría y global. |
| `app/report/` | Arma el informe en memoria. No hay tabla de informes. |
| `app/security/` | Cabeceras (CSP, HSTS…), CSRF, rate limiting en Redis, redirección a HTTPS. |
| `app/api/` | Endpoints de análisis, fotos e informe. |
| `app/web/` | Plantillas Jinja y JS sin framework (sin paso de build en desarrollo). |

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
