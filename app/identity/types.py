from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class VerifiedIdentity:
    """Única forma de pasarle un sujeto a las fuentes: solo la crea el módulo de identidad
    a partir de una sesión válida, así ninguna fuente recibe un email elegido a mano."""

    user_id: int
    email: str
