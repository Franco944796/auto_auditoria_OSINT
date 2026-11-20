from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field

from app.identity.types import VerifiedIdentity


class Category(StrEnum):
    BREACHES = "breaches"
    PASSWORDS = "passwords"
    PHOTOS = "photos"
    # Fuera del MVP: LINKED_ACCOUNTS (revisión por OAuth) y DATA_BROKERS (lista curada de opt-out).


class Finding(BaseModel):
    """Un hecho observado por una fuente. La severidad y la remediación las decide analysis/."""

    model_config = ConfigDict(extra="forbid")

    source: str = Field(max_length=40)
    category: Category
    code: str = Field(max_length=60)
    title: str = Field(max_length=300)
    detail: str = Field(default="", max_length=5000)
    data: dict[str, Any] = Field(default_factory=dict)


class SourceError(Exception):
    """El mensaje se muestra tal cual al usuario: sin datos internos."""


class Source[P](ABC):
    name: ClassVar[str]
    display_name: ClassVar[str] = ""
    homepage: ClassVar[str] = ""
    category: ClassVar[Category]
    runs_in_background: ClassVar[bool] = False

    @abstractmethod
    async def collect(self, identity: VerifiedIdentity, payload: P) -> list[Finding]:
        """Hallazgos SOLO del sujeto verificado; payload son datos que aporta el propio usuario."""
