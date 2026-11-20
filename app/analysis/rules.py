from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from app.sources.base import Finding


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


SEVERITY_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3}


@dataclass(frozen=True, slots=True)
class Assessment:
    severity: Severity
    remediation: list[str]


Rule = Callable[[Finding], Assessment]
RULES: dict[str, Rule] = {}


def rule(code: str) -> Callable[[Rule], Rule]:
    def register(function: Rule) -> Rule:
        RULES[code] = function
        return function

    return register


def assess_finding(finding: Finding) -> Assessment:
    return RULES.get(finding.code, _unknown)(finding)


def _unknown(finding: Finding) -> Assessment:
    return Assessment(Severity.LOW, ["Revisá este hallazgo y si no lo reconocés, consultanos."])


def _unique(steps: list[str]) -> list[str]:
    return list(dict.fromkeys(steps))


# Nombres de DataClasses tal como los devuelve la API de HIBP.
PASSWORD_CLASSES = {"Passwords", "Password hints", "Auth tokens"}
SECURITY_QUESTION_CLASSES = {"Security questions and answers", "Password hints"}
FINANCIAL_CLASSES = {
    "Credit cards",
    "Partial credit card data",
    "Credit card CVV",
    "Bank account numbers",
}
IDENTITY_DOC_CLASSES = {"Government issued IDs", "Social security numbers", "Passport numbers"}
PHONE_CLASSES = {"Phone numbers"}
PERSONAL_CLASSES = {"Physical addresses", "Dates of birth", "Geographic locations", "IP addresses"}

HIGH_CLASSES = (
    PASSWORD_CLASSES | SECURITY_QUESTION_CLASSES | FINANCIAL_CLASSES | IDENTITY_DOC_CLASSES
)
MEDIUM_CLASSES = PHONE_CLASSES | PERSONAL_CLASSES


@rule("breach.exposed")
def breach_exposed(finding: Finding) -> Assessment:
    classes = set(finding.data.get("data_classes", []))
    site = finding.title
    stealer = bool(finding.data.get("is_stealer_log"))

    if classes & HIGH_CLASSES or stealer:
        severity = Severity.HIGH
    elif classes & MEDIUM_CLASSES or finding.data.get("is_sensitive"):
        severity = Severity.MEDIUM
    else:
        severity = Severity.LOW

    steps: list[str] = []
    if stealer:
        steps.append(
            "Esta filtración viene de malware en un dispositivo: analizalo con un antivirus y "
            "cambiá las contraseñas guardadas en el navegador desde un equipo limpio."
        )
    if classes & PASSWORD_CLASSES:
        steps += [
            f"Cambiá la contraseña de {site} si todavía tenés cuenta.",
            "Cambiá esa misma contraseña en cualquier otro sitio donde la hayas repetido.",
            "Usá un gestor de contraseñas para tener una distinta en cada sitio.",
            f"Activá la verificación en dos pasos (2FA) en {site} y, sobre todo, en tu email.",
        ]
    if classes & SECURITY_QUESTION_CLASSES:
        steps.append(
            "Cambiá tus preguntas de seguridad: usá respuestas inventadas y guardalas en el gestor."
        )
    if classes & FINANCIAL_CLASSES:
        steps.append(
            "Revisá los movimientos de tus tarjetas y cuentas, avisá a tu banco y pedí una "
            "tarjeta nueva si la expuesta sigue vigente."
        )
    if classes & IDENTITY_DOC_CLASSES:
        steps.append(
            "Estate atento a créditos o cuentas abiertas a tu nombre y consultá en el organismo "
            "emisor cómo denunciar o bloquear el documento expuesto."
        )
    if classes & PHONE_CLASSES:
        steps.append(
            f"Desconfiá de SMS y llamadas que mencionen {site} y pedile a tu operador un PIN "
            "contra el duplicado de SIM (SIM swapping)."
        )
    if classes & PERSONAL_CLASSES:
        steps.append(
            "Esperá estafas personalizadas con estos datos: no confirmes información personal "
            "por teléfono, mensaje ni email."
        )
    steps.append(
        f"Desconfiá de correos que mencionen {site}: no abras sus enlaces y entrá escribiendo "
        "la dirección a mano."
    )
    return Assessment(severity, _unique(steps))


PASSWORD_STEPS = [
    "Dejá de usar esta contraseña en todos los sitios: ya figura en listas que usan los atacantes.",
    "Cambiala primero en tu email, bancos y redes sociales.",
    "Usá un gestor de contraseñas para generar una única y larga para cada sitio.",
    "Activá la verificación en dos pasos (2FA) donde puedas.",
]


@rule("password.compromised")
def password_compromised(finding: Finding) -> Assessment:
    return Assessment(Severity.HIGH, PASSWORD_STEPS)


@rule("password.clean")
def password_clean(finding: Finding) -> Assessment:
    return Assessment(
        Severity.INFO,
        ["No aparece en filtraciones conocidas. Asegurate de que sea única para cada sitio."],
    )


CLEAN_PHOTO_STEP = "Descargá la versión sin metadatos y compartí esa en lugar de la original."


@rule("exif.gps")
def exif_gps(finding: Finding) -> Assessment:
    return Assessment(
        Severity.HIGH,
        [
            CLEAN_PHOTO_STEP,
            "Desactivá la ubicación en la cámara. iPhone: Ajustes > Privacidad y seguridad > "
            "Localización > Cámara > Nunca. Android: en los ajustes de la app Cámara, desactivá "
            "«Guardar ubicación» o «Etiquetas de ubicación».",
            "Revisá si publicaste fotos originales en sitios que no borran los metadatos "
            "(foros, blogs, almacenamiento compartido) y reemplazalas.",
        ],
    )


@rule("exif.identifiers")
def exif_identifiers(finding: Finding) -> Assessment:
    return Assessment(
        Severity.MEDIUM,
        [
            CLEAN_PHOTO_STEP,
            "Los números de serie permiten vincular entre sí todas las fotos de tu cámara.",
            "Si la cámara tiene tu nombre configurado como dueño o autor, borralo en sus ajustes.",
        ],
    )


@rule("exif.device")
@rule("exif.datetime")
@rule("exif.software")
@rule("exif.embedded_metadata")
def exif_minor(finding: Finding) -> Assessment:
    return Assessment(Severity.LOW, [CLEAN_PHOTO_STEP])


@rule("exif.clean")
def exif_clean(finding: Finding) -> Assessment:
    return Assessment(Severity.INFO, ["Esta foto no revela metadatos sensibles."])
