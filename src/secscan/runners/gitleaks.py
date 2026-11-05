"""Gitleaks: secretos en el código."""

import json
import tempfile
from pathlib import Path

from secscan.gitutil import CLONE_ARGS, MIRROR_NAME, ensure_git_repo
from secscan.models import Category, Finding, Severity
from secscan.runners.base import CONTAINER_ROOT, Runner, RunnerError, RunnerOutput, read_report, relative_path


def parse_gitleaks(data: list[dict], root: str = CONTAINER_ROOT) -> list[Finding]:
    """Convierte el JSON de Gitleaks. Función pura: se prueba con ficheros guardados."""
    findings = []
    for item in data:
        findings.append(
            Finding(
                tool="gitleaks",
                rule_id=item["RuleID"],
                title=item["RuleID"].replace("-", " ").capitalize(),
                # En modo historial el hallazgo puede estar en un commit antiguo que ya no está en el árbol.
                description=item.get("Description", "") + (f" (commit {item['Commit'][:8]})" if item.get("Commit") else ""),
                # Un secreto filtrado es grave por defecto; el triaje decide si es de prueba.
                severity=Severity.HIGH,
                category=Category.SECRET,
                file=relative_path(item["File"], root),
                line_start=item.get("StartLine"),
                line_end=item.get("EndLine"),
                # Con --redact, Match ya viene enmascarado. Nunca se usa el campo Secret.
                snippet=item.get("Match", ""),
            )
        )
    return findings


# Claves de git que ejecutan programas. Las variables GIT_CONFIG_* pesan más que el .git/config del repo
# escaneado, así que ese repo no puede volver a activarlas.
NEUTRALIZED_GIT_CONFIG = {
    "log.showSignature": "false",
    "gpg.program": "false",
    "gpg.ssh.program": "false",
    "gpg.x509.program": "false",
    "core.fsmonitor": "false",
    "core.hooksPath": "/dev/null",
    "diff.external": "",
}


def git_env() -> dict[str, str]:
    env = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_COUNT": str(len(NEUTRALIZED_GIT_CONFIG))}
    for index, (key, value) in enumerate(NEUTRALIZED_GIT_CONFIG.items()):
        env[f"GIT_CONFIG_KEY_{index}"] = key
        env[f"GIT_CONFIG_VALUE_{index}"] = value
    return env


class GitleaksRunner(Runner):
    name = "gitleaks"
    image = "zricethezav/gitleaks:latest"
    network = "none"  # trabaja solo con ficheros locales: no necesita internet
    # El historial se lee con `git log -p` dentro de un repo que no es nuestro: git no debe cargar la
    # configuración global ni la del sistema. La del propio repo se neutraliza con --log-opts (abajo).
    env = git_env()

    def __init__(self, history: bool = False):
        # Con history=True revisa todos los commits: encuentra secretos borrados que siguen en el historial.
        self.history = history

    def run(self, target: Path) -> RunnerOutput:
        if not self.history:
            return super().run(target)
        # El historial se lee de un clon limpio y desechable, nunca del repo original: así su
        # .git/config (que no es nuestro) no llega a git. El clon se hace dentro del contenedor
        # (sin red, sin root, repo en solo lectura), no en el host. Las defensas de abajo son una segunda barrera.
        ensure_git_repo(target)
        with tempfile.TemporaryDirectory(prefix="secscan-mirror-") as tmp:  # 0700
            self._docker(target, Path(tmp), args=CLONE_ARGS, entrypoint="git")
            return super().run(Path(tmp) / MIRROR_NAME)

    def args(self) -> list[str]:
        return [
            "detect", "--source", CONTAINER_ROOT,
            *(
                # --no-textconv / --no-ext-diff / --no-show-signature: un `.git/config` ajeno puede declarar filtros
                # o programas (gpg) que ejecutan comandos. Ver también NEUTRALIZED_GIT_CONFIG.
                ["--log-opts", "--full-history --all --no-textconv --no-ext-diff --no-show-signature"]
                if self.history
                else ["--no-git"]  # por defecto, solo el árbol de trabajo
            ),
            "--redact",  # el valor del secreto nunca sale del contenedor
            "--exit-code", "0",  # encontrar secretos no es un fallo de la herramienta
            "--report-format", "json", "--report-path", "/out/gitleaks.json",
        ]  # fmt: skip

    def parse(self, out_dir: Path) -> RunnerOutput:
        # Sin informe no sabemos si hay secretos: read_report falla en vez de dar "limpio" en falso.
        try:
            data = json.loads(read_report(out_dir, "gitleaks.json") or "[]")
        except json.JSONDecodeError as error:
            raise RunnerError(f"informe de gitleaks ilegible: {error}") from None
        return RunnerOutput(findings=parse_gitleaks(data), scanned=["."])
