"""Preparación del clon limpio para `--history`.

El clon NO se hace en el host: un repo ajeno es entrada no confiable y git, al procesarlo, ha tenido
vulnerabilidades (enlaces simbólicos en `.git/objects`, configuración que ejecuta programas…).
Se hace dentro del mismo contenedor que escanea: sin red, sin root, con el repo en solo lectura.
"""

from pathlib import Path

from secscan.runners.base import CONTAINER_ROOT, RunnerError

MIRROR_NAME = "repo.git"

# Se ejecuta con `git` como entrypoint del contenedor de Gitleaks (que ya trae git).
# --local copia los ficheros de objetos; --no-hardlinks evita compartir ficheros con el original.
# git genera su propio .git/config en el clon: el del repo escaneado no se copia.
CLONE_ARGS = [
    "clone", "--mirror", "--local", "--no-hardlinks", "--quiet", "--",
    CONTAINER_ROOT, f"/out/{MIRROR_NAME}",
]  # fmt: skip


def ensure_git_repo(source: Path) -> None:
    """Exige un `.git` que sea un directorio real.

    Un `.git` que sea un enlace simbólico podría apuntar fuera del repo; uno que sea un fichero
    (worktrees, submódulos) redirige a otro directorio que no estaría montado en el contenedor.
    """
    git_dir = source / ".git"
    if git_dir.is_symlink() or not git_dir.is_dir():
        raise RunnerError("--history necesita un repositorio git con un directorio .git propio (no enlace ni fichero)")
