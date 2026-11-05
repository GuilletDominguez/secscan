"""Orquestador: lanza los runners, junta, deduplica, aplica el triaje y ordena."""

from collections.abc import Sequence
from datetime import UTC, datetime
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from secscan.config import Config
from secscan.hostile import find_hostile_content
from secscan.models import Finding, ScanResult
from secscan.preflight import unreadable_warning
from secscan.runners.base import Runner, RunnerError, RunnerOutput
from secscan.runners.gitleaks import GitleaksRunner
from secscan.runners.semgrep import SemgrepRunner
from secscan.runners.trivy import TrivyImageRunner, TrivyRunner
from secscan.runners.zap import ZapRunner
from secscan.targets import WebTarget

RUNNERS: dict[str, type[Runner]] = {
    "gitleaks": GitleaksRunner,
    "semgrep": SemgrepRunner,
    "trivy": TrivyRunner,
}


def _dedupe(findings: Sequence[Finding]) -> list[Finding]:
    """Quita repetidos exactos (misma huella en la misma línea)."""
    seen: set[tuple[str, int | None]] = set()
    unique = []
    for finding in findings:
        key = (finding.fingerprint, finding.line_start)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def _sort_key(finding: Finding):
    return (-finding.severity, finding.file, finding.line_start or 0, finding.rule_id)


def build_result(
    target: Path,
    outputs: dict[str, RunnerOutput],
    errors: dict[str, str],
    config: Config,
    warnings: list[str] | None = None,
) -> ScanResult:
    """Junta las salidas ya obtenidas. Separada de `scan` para probarla sin Docker."""
    everything = _dedupe([f for output in outputs.values() for f in output.findings])
    kept = [f for f in everything if not config.is_ignored(f)]
    scanned = {name: output.scanned for name, output in outputs.items()}
    # Solo lo que acabará en el informe: los hallazgos ignorados no se muestran.
    alerts, hits = find_hostile_content(kept, errors, warnings or [], scanned)
    return ScanResult(
        target=str(target),
        scanned_at=datetime.now(UTC).isoformat(timespec="seconds"),
        findings=sorted(kept, key=_sort_key),
        scanned=scanned,
        errors=errors,
        suppressed=len(everything) - len(kept),
        warnings=warnings or [],
        alerts=alerts,
        hostile_hits=hits,
    )


def make_runner(name: str, history: bool, semgrep_metrics: bool = True) -> Runner:
    # `history` solo tiene sentido para Gitleaks (revisar todos los commits) y `semgrep_metrics` para Semgrep.
    if name == "gitleaks":
        return GitleaksRunner(history=history)
    if name == "semgrep":
        return SemgrepRunner(metrics=semgrep_metrics)
    return RUNNERS[name]()


def scan(
    target: Path, tools: Sequence[str], config: Config, history: bool = False, semgrep_metrics: bool = True
) -> ScanResult:
    runners = [make_runner(name, history, semgrep_metrics) for name in tools]
    outputs: dict[str, RunnerOutput] = {}
    errors: dict[str, str] = {}

    def run(runner: Runner) -> tuple[str, RunnerOutput | RunnerError]:
        try:
            return runner.name, runner.run(target)
        except RunnerError as error:
            return runner.name, error

    # Los escáneres son procesos independientes: en paralelo tardan lo que el más lento.
    with ThreadPoolExecutor(max_workers=len(runners)) as pool:
        for name, outcome in pool.map(run, runners):
            if isinstance(outcome, RunnerError):
                errors[name] = str(outcome)
            else:
                outputs[name] = outcome
    return build_result(target, outputs, errors, config, unreadable_warning(target))


def _scan_one(runner: Runner, label: str, config: Config) -> ScanResult:
    """Un escaneo de una sola herramienta sobre un destino que no es un directorio (URL o imagen)."""
    outputs: dict[str, RunnerOutput] = {}
    errors: dict[str, str] = {}
    try:
        outputs[runner.name] = runner.run(None)
    except RunnerError as error:
        errors[runner.name] = str(error)
    return build_result(Path(label), outputs, errors, config)


def scan_web(target: WebTarget, config: Config, minutes: int = 1) -> ScanResult:
    result = _scan_one(ZapRunner(target, minutes), target.url, config)
    result.target = target.url  # Path() normaliza «http://» a «http:/»: se restaura la URL tal cual
    return result


def scan_image(image: str, config: Config) -> ScanResult:
    result = _scan_one(TrivyImageRunner(image), image, config)
    result.target = image
    return result
