from pydantic import BaseModel, ConfigDict


class StrictModel(BaseModel):
    """Rechaza campos de más: nadie puede colar un 'email' u otro sujeto en una petición."""

    model_config = ConfigDict(extra="forbid")
