"""Trivy: dependencias vulnerables (SCA) y malas configuraciones (Dockerfile, IaC)."""

import json
import subprocess
import tempfile
from pathlib import Path

from secscan.models import Category, Finding, Severity
from secscan.runners.base import CONTAINER_ROOT, Runner, RunnerError, RunnerOutput, read_report, relative_path

# La base de datos de vulnerabilidades pesa ~130 MB: sin caché se descarga en cada escaneo.
# Es un directorio del usuario (no un volumen de Docker) porque el contenedor corre con su uid.
CACHE_DIR = Path.home() / ".cache" / "secscan" / "trivy"


def _vulnerability(vuln: dict, file: str, category: Category) -> Finding:
    fixed = vuln.get("FixedVersion")
    package = f"{vuln['PkgName']}@{vuln['InstalledVersion']}"
    return Finding(
        tool="trivy",
        rule_id=vuln["VulnerabilityID"],
        title=vuln.get("Title") or vuln["VulnerabilityID"],
        description=f"{package}. " + (f"Corregido en {fixed}." if fixed else "Sin versión corregida."),
        severity=Severity.parse(vuln.get("Severity", "")),
        category=category,
        file=file,
        snippet=package,  # identifica la dependencia concreta en la huella
    )


def parse_trivy(data: dict, root: str = CONTAINER_ROOT) -> RunnerOutput:
    """Convierte el JSON de Trivy. Devuelve también los objetivos analizados."""
    findings, scanned = [], []
    for result in data.get("Results", []):
        target = relative_path(result["Target"], root)
        scanned.append(target)  # incluso sin hallazgos: haber mirado y no encontrar nada es un dato

        for vuln in result.get("Vulnerabilities") or []:
            findings.append(_vulnerability(vuln, target, Category.DEPENDENCY))

        for misconf in result.get("Misconfigurations") or []:
            if misconf.get("Status") != "FAIL":  # Trivy también lista las comprobaciones superadas
                continue
            cause = misconf.get("CauseMetadata", {})
            findings.append(
                Finding(
                    tool="trivy",
                    rule_id=misconf["ID"],
                    title=misconf["Title"],
                    description=misconf.get("Resolution") or misconf.get("Description", ""),
                    severity=Severity.parse(misconf.get("Severity", "")),
                    category=Category.CONFIG,
                    file=target,
                    line_start=cause.get("StartLine"),
                    line_end=cause.get("EndLine"),
                    snippet=misconf.get("Message", ""),
                )
            )
    return RunnerOutput(findings=findings, scanned=scanned)


def parse_trivy_image(data: dict, image: str) -> RunnerOutput:
    """Convierte el JSON de `trivy image`: paquetes del sistema, paquetes de lenguaje y secretos en capas."""
    findings, scanned = [], []
    for result in data.get("Results", []):
        target = result["Target"]
        # Trivy nombra el objetivo del SO con el punto de montaje interno («/target (alpine 3.15.0)»):
        # se sustituye por el nombre de la imagen que escribió el usuario.
        label = image + target[len("/target") :] if target.startswith("/target ") else relative_path(target, "/")
        scanned.append(label)
        is_os = result.get("Class") == "os-pkgs"

        for vuln in result.get("Vulnerabilities") or []:
            # Un paquete de lenguaje se localiza mejor por su ruta que por el nombre genérico («Python»).
            where = vuln.get("PkgPath") or label
            findings.append(_vulnerability(vuln, where if not is_os else label, Category.IMAGE if is_os else Category.DEPENDENCY))

        for secret in result.get("Secrets") or []:
            findings.append(
                Finding(
                    tool="trivy",
                    rule_id=secret["RuleID"],
                    title=secret.get("Title") or secret["RuleID"],
                    description=f"Secreto ({secret.get('Category', 'desconocido')}) dentro de una capa de la imagen.",
                    severity=Severity.parse(secret.get("Severity", "")),
                    category=Category.SECRET,
                    file=label,
                    line_start=secret.get("StartLine"),
                    line_end=secret.get("EndLine"),
                    snippet=secret.get("Match", ""),  # Trivy ya lo enmascara (****)
                )
            )
    return RunnerOutput(findings=findings, scanned=scanned)


class TrivyRunner(Runner):
    name = "trivy"
    image = "aquasec/trivy:latest"

    def args(self) -> list[str]:
        return [
            "fs", "--quiet", "--cache-dir", "/cache", "--scanners", "vuln,misconfig",
            "--format", "json", "--output", "/out/trivy.json", CONTAINER_ROOT,
        ]  # fmt: skip

    def extra_mounts(self) -> list[str]:
        CACHE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        return ["-v", f"{CACHE_DIR}:/cache"]

    def parse(self, out_dir: Path) -> RunnerOutput:
        try:
            return parse_trivy(json.loads(read_report(out_dir, "trivy.json")))
        except json.JSONDecodeError as error:
            raise RunnerError(f"informe de trivy ilegible: {error}") from None


class TrivyImageRunner(TrivyRunner):
    """Escanea una imagen de Docker que ya está en local.

    La imagen se exporta a un .tar con `docker save` y Trivy lee ese fichero. Así NO se monta el
    socket de Docker en el contenedor (daría control total del host) ni hace falta que Trivy hable con
    el demonio. El .tar se borra al terminar.
    """

    def __init__(self, image: str):
        self.target_image = image  # ya validado por validate_image_name

    def args(self) -> list[str]:
        return [
            "image", "--quiet", "--cache-dir", "/cache", "--input", CONTAINER_ROOT,
            "--scanners", "vuln,secret",
            "--format", "json", "--output", "/out/trivy.json",
        ]  # fmt: skip

    def run(self, target: Path | None = None) -> RunnerOutput:
        self._ensure_local()
        # El directorio es privado (0700) y el .tar sale con permisos 0600: solo nuestro usuario lo lee.
        with tempfile.TemporaryDirectory(prefix="secscan-image-") as tmp:
            tar = Path(tmp) / "image.tar"
            self._docker_cli("save", "-o", str(tar), self.target_image)
            return super().run(tar)

    def parse(self, out_dir: Path) -> RunnerOutput:
        try:
            return parse_trivy_image(json.loads(read_report(out_dir, "trivy.json")), self.target_image)
        except json.JSONDecodeError as error:
            raise RunnerError(f"informe de trivy ilegible: {error}") from None
        except (KeyError, TypeError) as error:
            raise RunnerError(f"informe de trivy con formato inesperado: {error}") from None

    def _ensure_local(self) -> None:
        done = self._docker_cli("image", "inspect", self.target_image, check=False)
        if done.returncode != 0:
            raise RunnerError(f"la imagen «{self.target_image}» no está en local: descárgala antes con `docker pull`")

    def _docker_cli(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        try:
            done = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=self.timeout_seconds)
        except FileNotFoundError:
            raise RunnerError("Docker no está instalado o no está en el PATH") from None
        except subprocess.TimeoutExpired:
            raise RunnerError(f"docker {args[0]} superó {self.timeout_seconds}s") from None
        if check and done.returncode != 0:
            detail = (done.stderr or done.stdout).strip().splitlines()[-1:] or ["sin detalle"]
            raise RunnerError(f"docker {args[0]} falló: {detail[0]}")
        return done
