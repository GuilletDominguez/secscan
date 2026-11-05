"""Comprobaciones previas al escaneo."""

import os
from pathlib import Path

LIMIT = 10  # cuántos ejemplos se muestran en el aviso


def unreadable_paths(root: Path) -> list[str]:
    """Ficheros y directorios que nuestro usuario no puede leer, relativos a `root`.

    Los contenedores corren con nuestro uid, así que lo que no podemos leer aquí tampoco
    lo leerán las herramientas: quedaría sin analizar y el informe diría «limpio» sin serlo.
    """
    found: list[str] = []

    def on_error(error: OSError) -> None:  # os.walk calla los directorios que no puede abrir
        if error.filename:
            found.append(os.path.relpath(error.filename, root))

    for current, _dirs, files in os.walk(root, onerror=on_error):
        for name in files:
            path = os.path.join(current, name)
            if not os.path.islink(path) and not os.access(path, os.R_OK):
                found.append(os.path.relpath(path, root))
    return sorted(found)


def unreadable_warning(root: Path) -> list[str]:
    paths = unreadable_paths(root)
    if not paths:
        return []
    shown = ", ".join(paths[:LIMIT]) + (" …" if len(paths) > LIMIT else "")
    return [f"{len(paths)} ruta(s) sin permiso de lectura, no analizadas: {shown}"]
