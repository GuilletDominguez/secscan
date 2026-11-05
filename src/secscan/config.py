"""Configuración del repo escaneado (`.secscan.yml`): rutas y reglas que se ignoran.

Ejemplo:

    ignore:
      paths: ["**/tests/**"]            # glob; ** cruza directorios
      rules: [dependabot-missing-cooldown]
      findings:                          # huellas concretas, siempre con motivo
        - id: 3f9a1c2b7d4e8a10
          reason: URL fija de configuración, no viene de la petición
"""

from pathlib import Path, PurePosixPath

import yaml
from pydantic import BaseModel, Field, ValidationError, model_validator

from secscan.models import Finding

CONFIG_FILE = ".secscan.yml"


class IgnoredFinding(BaseModel):
    id: str
    reason: str  # obligatorio: una supresión sin justificación es una deuda oculta


class Ignore(BaseModel):
    paths: list[str] = Field(default_factory=list)
    rules: list[str] = Field(default_factory=list)
    findings: list[IgnoredFinding] = Field(default_factory=list)


class Config(BaseModel):
    ignore: Ignore = Field(default_factory=Ignore)

    @model_validator(mode="before")
    @classmethod
    def _empty_file(cls, data):
        return data or {}  # un YAML vacío se lee como None

    def is_ignored(self, finding: Finding) -> bool:
        path = PurePosixPath(finding.file)
        return (
            finding.rule_id in self.ignore.rules
            or any(path.full_match(pattern) for pattern in self.ignore.paths)
            or finding.fingerprint in {item.id for item in self.ignore.findings}
        )


class ConfigError(Exception):
    pass


def load_config(root: Path) -> Config:
    """Lee `.secscan.yml` de la raíz escaneada. Sin fichero, no se ignora nada."""
    path = root / CONFIG_FILE
    return load_config_file(path) if path.is_file() else Config()


def load_config_file(path: Path) -> Config:
    """Lee un fichero de configuración concreto (para los escaneos que no son de un repo)."""
    try:
        # safe_load: nunca ejecuta código del repo analizado.
        return Config.model_validate(yaml.safe_load(path.read_text()))
    except (yaml.YAMLError, ValidationError) as error:
        raise ConfigError(f"{CONFIG_FILE} no es válido: {error}") from None
