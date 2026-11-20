import html
import re

_TAG = re.compile(r"<[^>]+>")


def plain_text(markup: str) -> str:
    return html.unescape(_TAG.sub("", markup)).strip()


# Nombres de tipos de datos tal como los usan HIBP y XposedOrNot.
DATA_CLASS_ES = {
    "Email addresses": "emails",
    "Passwords": "contraseñas",
    "Password hints": "pistas de contraseña",
    "Usernames": "nombres de usuario",
    "Names": "nombres",
    "Phone numbers": "teléfonos",
    "Physical addresses": "direcciones",
    "Dates of birth": "fechas de nacimiento",
    "Geographic locations": "ubicaciones",
    "IP addresses": "direcciones IP",
    "Genders": "género",
    "Credit cards": "tarjetas de crédito",
    "Partial credit card data": "datos parciales de tarjetas",
    "Bank account numbers": "cuentas bancarias",
    "Security questions and answers": "preguntas de seguridad",
    "Government issued IDs": "documentos de identidad",
    "Social security numbers": "números de seguridad social",
    "Passport numbers": "pasaportes",
    "Auth tokens": "tokens de sesión",
    "Job titles": "puestos de trabajo",
    "Employers": "empleadores",
    "Social media profiles": "perfiles de redes sociales",
}


def data_classes_es(classes: list[str]) -> list[str]:
    return [DATA_CLASS_ES.get(name, name) for name in classes]
