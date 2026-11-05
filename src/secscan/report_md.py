"""Informe en Markdown: portable, para pegar en un PR, una wiki o un issue."""

import re

from secscan.models import Finding, ScanResult
from secscan.report import LABELS, display_name, grouped, shown_hits

ZERO_WIDTH_SPACE = "\u200b"
_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+!|~>])")
MAX_TEXT = 300


def escape(value: object) -> str:
    """Escapa texto que viene del repo escaneado (no es de fiar).

    Sin esto, un título como `[clic](http://malo)` o `<img src=x onerror=...>` se renderizaría,
    y un `|` o un salto de línea rompería la tabla.
    """
    text = " ".join(str(value).split())  # los saltos de línea rompen las filas de las tablas
    text = text.replace("&", "&amp;").replace("<", "&lt;")
    text = _SPECIAL.sub(r"\\\1", text)
    # En un comentario de GitHub, `@usuario` notifica a esa persona y `#123` enlaza (y deja una referencia en)
    # esa incidencia. Un repo hostil podría llamar a un fichero `@alguien`. Un espacio de ancho cero tras el
    # símbolo rompe el reconocimiento sin cambiar lo que se ve.
    text = text.replace("@", "@" + ZERO_WIDTH_SPACE).replace("#", "#" + ZERO_WIDTH_SPACE)
    return text if len(text) <= MAX_TEXT else text[:MAX_TEXT] + "…"


def _where(finding: Finding) -> str:
    return finding.file + (f":{finding.line_start}" if finding.line_start else "")


def to_markdown(result: ScanResult) -> str:
    lines = [f"# Informe de seguridad · {escape(display_name(result))}", ""]
    meta = []
    if result.scanned_at:
        meta.append(f"Generado: {result.scanned_at}")  # lo genera secscan: no es entrada no confiable
    if result.scanned:
        meta.append("Herramientas: " + ", ".join(escape(tool) for tool in result.scanned))
    if meta:
        lines += [" · ".join(meta), ""]

    # Lo primero que debe ver quien lee: si el resultado es fiable.
    for alert in result.alerts:
        lines += [f"> 🚨 **Contenido sospechoso en el repo escaneado.** {escape(alert)}", ""]
    if result.hostile_hits:
        hits, more = shown_hits(result)
        lines += ["### Fragmentos a revisar", "", "| Dónde | Campo | Tipo | Fragmento |", "|---|---|---|---|"]
        for hit in hits:
            lines.append(f"| {escape(hit.where)} | {escape(hit.field)} | {escape(hit.kind)} | {escape(hit.fragment)} |")
        if more:
            lines.append(f"\n… y {more} más (están todas en el informe JSON)")
        lines.append("")
    if result.errors:
        failed = ", ".join(escape(tool) for tool in result.errors)
        lines += [f"> ⚠️ **Escaneo incompleto.** Fallaron: {failed}. Un resultado sin hallazgos no significa «limpio».", ""]
    elif not result.findings:
        lines += ["> ✅ Sin hallazgos.", ""]

    lines += ["## Resumen", "", "| Severidad | Hallazgos |", "|---|---:|"]
    groups = grouped(result)
    counts = {severity: len(found) for severity, found in groups}
    for severity, label in LABELS.items():
        lines.append(f"| {label} | {counts.get(severity, 0)} |")
    total = f"**Total: {len(result.findings)}**"
    lines += ["", total + (f" · {result.suppressed} ignorados por `.secscan.yml`" if result.suppressed else ""), ""]

    if groups:
        lines += ["## Hallazgos", ""]
    for severity, found in sorted(groups, key=lambda group: -group[0]):
        lines += [f"### {LABELS[severity]} ({len(found)})", ""]
        lines += ["| Herramienta | Regla | Ubicación | Título | Huella |", "|---|---|---|---|---|"]
        for f in found:
            lines.append(
                f"| {escape(f.tool)} | {escape(f.rule_id)} | {escape(_where(f))} | {escape(f.title)} | `{f.fingerprint}` |"
            )
        lines.append("")
        for f in found:
            if f.description:
                lines.append(f"- **{escape(f.rule_id)}** en {escape(_where(f))}: {escape(f.description)}")
        lines.append("")

    lines += ["## Cobertura", ""]
    for tool, targets in result.scanned.items():
        shown = ", ".join(escape(t) for t in targets) if 0 < len(targets) <= 4 else f"{len(targets)} objetivos"
        lines.append(f"- ✓ {escape(tool)}: analizado ({shown})")
    for tool, error in result.errors.items():
        lines.append(f"- ✗ {escape(tool)}: {escape(error)}")
    if not result.scanned and not result.errors:
        lines.append("- Sin datos de cobertura.")
    lines.append("")

    if result.warnings:
        lines += ["## Avisos", ""] + [f"- {escape(w)}" for w in result.warnings] + [""]

    lines += ["---"]
    if result.signed_by:
        lines += [f"Informe firmado por **{escape(result.signed_by)}**.", ""]
    lines += ["Generado con secscan. La huella de cada hallazgo sirve para ignorarlo en `.secscan.yml`.", ""]
    return "\n".join(lines)
