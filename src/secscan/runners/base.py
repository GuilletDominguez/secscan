"""Interfaz común de los runners y la ejecución de contenedores."""

import os
import shutil
import stat
import subprocess
import tempfile
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from secscan.models import Finding

# Punto de montaje del repo dentro del contenedor. Las rutas que devuelven las
# herramientas empiezan por aquí y hay que quitarlo para dejarlas relativas.
CONTAINER_ROOT = "/target"
TIMEOUT_SECONDS = 600


class RunnerError(Exception):
    """La herramienta no pudo ejecutarse o devolvió algo ilegible."""


@dataclass
class RunnerOutput:
    findings: list[Finding] = field(default_factory=list)
    scanned: list[str] = field(default_factory=list)  # objetivos que la herramienta sí analizó


def read_report(out_dir: Path, filename: str) -> str:
    """Lee el informe de la herramienta, comprobando que es un fichero normal y nuestro.

    Defensa en profundidad: aunque el directorio es privado (0700), no se sigue un
    enlace simbólico ni se confía en un fichero de otro usuario.
    """
    path = out_dir / filename
    try:
        info = path.lstat()  # lstat: no sigue enlaces
    except FileNotFoundError:
        raise RunnerError(f"no se generó el informe {filename}") from None
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise RunnerError(f"el informe {filename} no es un fichero propio")
    return path.read_text()


def relative_path(path: str, root: str = CONTAINER_ROOT) -> str:
    """`/target/apps/x.py` -> `apps/x.py`. Así el mismo fichero coincide entre herramientas."""
    prefix = root.rstrip("/") + "/"
    return path[len(prefix) :] if path.startswith(prefix) else path.lstrip("/")


class Runner(ABC):
    name: str
    image: str
    # Red del contenedor. None = la de Docker por defecto; "none" = sin red.
    # Un runner que no necesita internet no debería tenerlo: si una herramienta se viera comprometida, no podría filtrar nada.
    network: str | None = None
    # Variables de entorno del contenedor.
    env: dict[str, str] = {}
    # Dónde ve el contenedor el directorio de informes (ZAP escribe en /zap/wrk).
    out_mount: str = "/out"
    timeout_seconds: int = TIMEOUT_SECONDS
    # Entrypoint del contenedor, si no es el de la imagen.
    entrypoint: str | None = None

    @abstractmethod
    def args(self) -> list[str]:
        """Argumentos de la herramienta. Escribe su informe en /out."""

    @abstractmethod
    def parse(self, out_dir: Path) -> RunnerOutput:
        """Lee el informe que dejó la herramienta en `out_dir`."""

    def run(self, target: Path | None) -> RunnerOutput:
        # El repo se monta de solo lectura: el escáner nunca modifica lo que analiza.
        # mkdtemp crea el directorio con permisos 0700: solo nuestro usuario puede tocarlo.
        # El contenedor corre con nuestro uid (ver _docker), así que puede escribir sin abrirlo a nadie más.
        out_dir = Path(tempfile.mkdtemp(prefix=f"secscan-{self.name}-"))
        try:
            self.prepare(out_dir)
            self._docker(target, out_dir)
            return self.parse(out_dir)
        finally:
            shutil.rmtree(out_dir, ignore_errors=True)

    def _docker(
        self, target: Path | None, out_dir: Path, args: list[str] | None = None, entrypoint: str | None = None
    ) -> None:
        # Nombre único: si el escaneo supera el tiempo (o se interrumpe) hay que poder matar ESE contenedor.
        # Sin esto, matar el cliente de Docker deja el contenedor corriendo, con su red y todo.
        container = f"secscan-{self.name}-{uuid.uuid4().hex[:12]}"
        entrypoint = entrypoint or self.entrypoint
        # Lista de argumentos, sin shell: la ruta del usuario nunca se interpreta como comando.
        command = [
            "docker", "run", "--rm", "--name", container,
            "--user", f"{os.getuid()}:{os.getgid()}",  # nunca root dentro del contenedor
            *(["--network", self.network] if self.network else []),
            *[arg for key, value in self.env.items() for arg in ("-e", f"{key}={value}")],
            "-e", "HOME=/tmp",  # con un uid arbitrario no hay HOME escribible: las herramientas guardan ahí su estado
            # Sin destino en disco (un escaneo web) no se monta nada del host.
            *(["-v", f"{target.resolve()}:{CONTAINER_ROOT}:ro"] if target is not None else []),
            "-v", f"{out_dir}:{self.out_mount}",
            *self.extra_mounts(),
            *self.extra_options(),
            *(["--entrypoint", entrypoint] if entrypoint else []),
            self.image, *(self.args() if args is None else args),
        ]  # fmt: skip
        try:
            done = subprocess.run(command, capture_output=True, text=True, timeout=self.timeout_seconds)
        except FileNotFoundError:
            raise RunnerError("Docker no está instalado o no está en el PATH") from None
        except subprocess.TimeoutExpired:
            self._kill(container)
            raise RunnerError(f"{self.name} superó {self.timeout_seconds}s") from None
        except KeyboardInterrupt:  # Ctrl-C: el contenedor tampoco debe quedarse corriendo
            self._kill(container)
            raise
        if done.returncode != 0:
            raise RunnerError(f"{self.name} terminó con código {done.returncode}: {self._detail(done)}")

    @staticmethod
    def _detail(done: subprocess.CompletedProcess) -> str:
        """Las últimas líneas con contenido del log, no solo la última (a menudo es un INFO sin relación)."""
        lines = [line.strip() for line in (done.stderr or done.stdout or "").splitlines() if line.strip()]
        text = " | ".join(lines[-3:]) or "sin detalle"
        return text if len(text) <= 300 else text[:299] + "…"

    @staticmethod
    def _kill(container: str) -> None:
        """Mata el contenedor (mejor esfuerzo: si ya terminó, no pasa nada)."""
        try:
            subprocess.run(["docker", "kill", container], capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            pass

    def prepare(self, out_dir: Path) -> None:
        """Deja en `out_dir` lo que el contenedor necesite antes de ejecutarse (p. ej. un plan)."""

    def extra_mounts(self) -> list[str]:
        """Montajes adicionales (p. ej. la caché de Trivy)."""
        return []

    def extra_options(self) -> list[str]:
        """Otras opciones de `docker run` (p. ej. `--add-host`)."""
        return []
