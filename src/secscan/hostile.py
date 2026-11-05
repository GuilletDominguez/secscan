"""Detecta texto del repo escaneado que intenta ejecutar código al abrir un informe.

Escapar y la CSP ya lo neutralizan, pero en silencio. Esto lo hace visible: un repo cuyo nombre de
fichero o mensaje lleva `<script>` o `onerror=` no es un repo cualquiera, y quien lee el informe debe saberlo.

Cada coincidencia se devuelve con su fragmento exacto para que una persona decida si es maliciosa o un
falso positivo. El fragmento es entrada no confiable: los informes lo muestran siempre escapado.
"""

import re
from collections.abc import Iterable, Mapping

from secscan.models import Finding, HostileHit

# Qué se busca. No es una lista exhaustiva de XSS: es una señal de aviso. La defensa real es escapar + CSP.
PATTERNS: dict[str, re.Pattern[str]] = {
    "etiqueta <script>": re.compile(r"<\s*/?\s*script", re.I),
    "manejador de eventos (onerror=…)": re.compile(r"<[^>]*\bon[a-z]{3,}\s*=", re.I),
    "etiqueta activa (iframe, object, embed, svg, img…)": re.compile(
        r"<\s*(iframe|object|embed|svg|img|link|meta|base|form)\b", re.I
    ),
    "URL javascript:": re.compile(r"javascript\s*:", re.I),
    "documento data:text/html": re.compile(r"data\s*:\s*text/html", re.I),
}
MAX_FRAGMENT = 120  # lo que se muestra de cada coincidencia
MAX_HITS = 20  # coincidencias que se detallan; el resto se cuenta


def _fragment(text: str, start: int) -> str:
    """La etiqueta que empieza en `start` (hasta su `>`), o una ventana corta si no hay `>`."""
    end = text.find(">", start)
    stop = end + 1 if 0 <= end - start < MAX_FRAGMENT else start + MAX_FRAGMENT
    piece = " ".join(text[start:stop].split())
    return piece if len(piece) < MAX_FRAGMENT else piece[: MAX_FRAGMENT - 1] + "…"


def _scan(text: str) -> list[tuple[str, str]]:
    """(tipo, fragmento) de cada coincidencia, sin repetir el mismo fragmento."""
    seen: set[str] = set()
    hits = []
    for kind, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            # Si el patrón empieza a mitad de etiqueta (p. ej. javascript: dentro de href), se retrocede al `<`.
            lt = text.rfind("<", 0, match.start() + 1)
            fragment = _fragment(text, lt if lt >= 0 else match.start())
            if fragment not in seen:
                seen.add(fragment)
                hits.append((kind, fragment))
    return hits


def find_hostile_content(
    findings: Iterable[Finding],
    errors: Mapping[str, str],
    warnings: Iterable[str],
    scanned: Mapping[str, Iterable[str]],
) -> tuple[list[str], list[HostileHit]]:
    """Devuelve (avisos, coincidencias) sobre campos del repo que parecen intentar ejecutar código.

    No se mira `snippet`: es código, y un repo legítimo con plantillas HTML lo contiene a menudo
    (`<script src=…>`), lo que llenaría de falsas alarmas. El snippet se escapa igual.
    """
    hits: list[HostileHit] = []

    def check(text: str, where: str, field: str) -> None:
        for kind, fragment in _scan(text):
            hits.append(HostileHit(where=where, field=field, kind=kind, fragment=fragment))

    for f in findings:
        where = f"{f.tool}/{f.rule_id}"
        check(f.file, where, "ruta")
        check(f.rule_id, where, "regla")
        check(f.title, where, "título")
        check(f.description, where, "descripción")
    for tool, error in errors.items():
        check(error, f"error de {tool}", "error")
    for index, warning in enumerate(warnings):
        check(warning, f"aviso {index + 1}", "aviso")
    for tool, targets in scanned.items():
        for target in targets:
            check(target, tool, "ruta analizada")

    if not hits:
        return [], []
    kinds = "; ".join(sorted({hit.kind for hit in hits}))
    alert = (
        f"{len(hits)} coincidencia(s) en el repo escaneado habrían ejecutado código al abrir el informe ({kinds}). "
        "Se neutralizaron: aparecen como texto inofensivo. Revisa abajo cada fragmento: puede ser un intento de "
        "ataque o un falso positivo. Mientras tanto, trata este repo como no confiable."
    )
    return [alert], hits
