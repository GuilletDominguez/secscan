"""Semgrep: vulnerabilidades en el código (SAST). Usa SARIF, el formato estándar."""

import json
import re
from pathlib import Path

from secscan.models import Category, Finding, Severity
from secscan.runners.base import CONTAINER_ROOT, Runner, RunnerError, RunnerOutput, read_report, relative_path

# Nivel SARIF -> severidad. Semgrep casi siempre dice "warning", por eso se ajusta con la confianza.
LEVELS = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "note": Severity.LOW, "none": Severity.INFO}


def _severity(level: str, tags: list[str]) -> Severity:
    severity = LEVELS.get(level, Severity.MEDIUM)
    if "LOW CONFIDENCE" in tags and severity > Severity.INFO:
        severity = Severity(severity - 1)  # una regla poco fiable no merece el nivel entero
    return severity


def _title(message: str, fallback: str) -> str:
    """Primera frase del mensaje de la regla. El nombre de las reglas de Semgrep es solo su id (`missing-user`)."""
    first = re.split(r"(?<=[.!?])\s", " ".join(message.split()), maxsplit=1)[0].rstrip(".")
    if not first:
        return fallback
    return first if len(first) <= 120 else first[:119].rstrip() + "…"


def parse_semgrep(sarif: dict, root: str = CONTAINER_ROOT) -> list[Finding]:
    """Convierte un SARIF de Semgrep. Función pura."""
    findings = []
    for run in sarif.get("runs", []):
        rules = {rule["id"]: rule for rule in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for result in run.get("results", []):
            # Semgrep incluye en el SARIF lo marcado con `# nosemgrep`, con "suppressions": ya está triado.
            if result.get("suppressions"):
                continue
            rule = rules.get(result["ruleId"], {})
            tags = rule.get("properties", {}).get("tags", [])
            level = result.get("level") or rule.get("defaultConfiguration", {}).get("level", "warning")
            location = result["locations"][0]["physicalLocation"]
            region = location.get("region", {})
            cwe = next((tag for tag in tags if tag.startswith("CWE-")), "")
            message = result.get("message", {}).get("text", "")
            findings.append(
                Finding(
                    tool="semgrep",
                    rule_id=result["ruleId"].rsplit(".", 1)[-1],  # el id completo es larguísimo
                    title=_title(message, rule.get("name", result["ruleId"]).rsplit(".", 1)[-1]),
                    description=f"{cwe}\n{message}".strip() if cwe else message,
                    severity=_severity(level, tags),
                    category=Category.CODE,
                    file=relative_path(location["artifactLocation"]["uri"], root),
                    line_start=region.get("startLine"),
                    line_end=region.get("endLine"),
                    snippet=region.get("snippet", {}).get("text", ""),
                )
            )
    return findings


# Conjunto de reglas del registro que se usa sin métricas. `--config auto` las exige («Cannot create auto
# config when metrics are off»), así que no se puede desactivar las métricas y conservar `auto`.
NO_METRICS_RULES = "p/default"


class SemgrepRunner(Runner):
    name = "semgrep"
    image = "semgrep/semgrep"

    def __init__(self, metrics: bool = True):
        # metrics=True (por defecto): `--config auto`, que descarga las reglas y envía métricas anónimas a Semgrep.
        # metrics=False: el conjunto fijo `p/default`, `--metrics off` y sin la comprobación de versión
        # (otro contacto con semgrep.dev). Las reglas se siguen descargando del registro.
        self.metrics = metrics

    def _rules_args(self) -> list[str]:
        if self.metrics:
            return ["--config", "auto"]
        return ["--config", NO_METRICS_RULES, "--metrics", "off", "--disable-version-check"]

    def args(self) -> list[str]:
        return [
            "semgrep", "scan", *self._rules_args(), "--quiet",
            "--sarif-output", "/out/semgrep.sarif",  # hallazgos (formato estándar)
            "--json-output", "/out/semgrep.json",  # solo para saber qué ficheros se analizaron: el SARIF no lo dice
            CONTAINER_ROOT,
        ]  # fmt: skip

    def parse(self, out_dir: Path) -> RunnerOutput:
        try:
            sarif = json.loads(read_report(out_dir, "semgrep.sarif"))
        except json.JSONDecodeError as error:
            raise RunnerError(f"informe de semgrep ilegible: {error}") from None
        return RunnerOutput(findings=parse_semgrep(sarif), scanned=self._scanned(out_dir))

    @staticmethod
    def _scanned(out_dir: Path) -> list[str]:
        try:
            paths = json.loads(read_report(out_dir, "semgrep.json"))["paths"]["scanned"]
        except (RunnerError, json.JSONDecodeError, KeyError):
            return ["."]  # sin la lista no sabemos más: cobertura genérica, pero los hallazgos siguen valiendo
        return sorted(relative_path(path) for path in paths)
