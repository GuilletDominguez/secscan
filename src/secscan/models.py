"""Modelo unificado: todas las herramientas se convierten a estos tipos."""

import hashlib
from enum import IntEnum, StrEnum

from pydantic import BaseModel, Field, computed_field


class Severity(IntEnum):
    """Orden numérico: permite comparar (`HIGH >= MEDIUM`) y ordenar."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError:
            return cls.INFO


class Category(StrEnum):
    CODE = "code"
    SECRET = "secret"
    DEPENDENCY = "dependency"
    CONFIG = "config"
    WEB = "web"  # hallazgo de un escaneo a una aplicación en ejecución
    NETWORK = "network"  # puerto o servicio expuesto de un host
    IMAGE = "image"  # vulnerabilidad en una imagen de contenedor


class Finding(BaseModel):
    tool: str
    rule_id: str
    title: str
    description: str = ""
    severity: Severity
    category: Category
    file: str  # siempre relativo a la raíz escaneada
    line_start: int | None = None
    line_end: int | None = None
    # Para secretos siempre va enmascarado: nunca guardamos el valor real.
    snippet: str = ""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fingerprint(self) -> str:
        """Identidad estable del hallazgo.

        No incluye el número de línea: si el código se mueve, sigue siendo el mismo
        hallazgo y un falso positivo ya marcado no vuelve a aparecer. Si no hay
        fragmento (p. ej. una dependencia), la línea no aporta nada de todos modos.
        """
        parts = (self.tool, self.rule_id, self.file, " ".join(self.snippet.split()))
        return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:16]


class HostileHit(BaseModel):
    """Una coincidencia de marcado sospechoso en texto del repo escaneado."""

    where: str  # p. ej. "semgrep/eval-detected"
    field: str  # ruta, título, descripción…
    kind: str  # qué tipo de marcado es
    fragment: str  # el fragmento exacto, recortado. Entrada no confiable: se muestra siempre escapado


class ScanResult(BaseModel):
    """Resultado completo de un escaneo, incluida la cobertura."""

    target: str
    scanned_at: str = ""  # ISO 8601, UTC
    findings: list[Finding] = Field(default_factory=list)
    # Qué se analizó: "0 hallazgos en 3 ficheros" no es lo mismo que "no se miró nada".
    scanned: dict[str, list[str]] = Field(default_factory=dict)  # herramienta -> objetivos
    errors: dict[str, str] = Field(default_factory=dict)  # herramienta -> fallo
    suppressed: int = 0  # hallazgos ocultos por .secscan.yml
    # Cosas que limitan la fiabilidad del resultado sin ser un fallo (p. ej. ficheros que no se pudieron leer).
    warnings: list[str] = Field(default_factory=list)
    # Más grave que un aviso: el repo escaneado parece intentar atacar a quien lea el informe.
    alerts: list[str] = Field(default_factory=list)
    # Quién firma el informe: lo decide quien ejecuta secscan (--signed-by). Por defecto, nadie.
    signed_by: str = ""
    hostile_hits: list[HostileHit] = Field(default_factory=list)  # el detalle de cada alerta, para revisarlo

    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)
