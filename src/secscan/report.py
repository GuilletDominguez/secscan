"""Salidas: tabla en terminal, JSON y SARIF."""

import json

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from secscan.models import ScanResult, Severity

COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
LABELS = {
    Severity.CRITICAL: "Crítica",
    Severity.HIGH: "Alta",
    Severity.MEDIUM: "Media",
    Severity.LOW: "Baja",
    Severity.INFO: "Info",
}


def grouped(result: ScanResult) -> list[tuple[Severity, list]]:
    """Hallazgos agrupados por severidad, de más a menos grave, sin los grupos vacíos."""
    groups = []
    for severity in sorted(Severity, reverse=True):
        found = [f for f in result.findings if f.severity == severity]
        if found:
            groups.append((severity, found))
    return groups


def shown_hits(result: ScanResult) -> tuple[list, int]:
    """Coincidencias que se detallan y cuántas quedan sin detallar (para no llenar el informe)."""
    from secscan.hostile import MAX_HITS

    return result.hostile_hits[:MAX_HITS], max(0, len(result.hostile_hits) - MAX_HITS)


def display_name(result: ScanResult) -> str:
    """Solo el nombre del directorio: un informe que se comparte no debe revelar rutas ni usuarios del equipo."""
    if "://" in result.target:  # un escaneo web: el host, sin ruta ni credenciales
        from urllib.parse import urlsplit

        return urlsplit(result.target).hostname or result.target
    return result.target.rstrip("/").rsplit("/", 1)[-1] or result.target


SARIF_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def to_json(result: ScanResult) -> str:
    return result.model_dump_json(indent=2)


def to_sarif(result: ScanResult) -> str:
    rules: dict[str, dict] = {}
    results = []
    for f in result.findings:
        rules.setdefault(f"{f.tool}/{f.rule_id}", {
            "id": f"{f.tool}/{f.rule_id}",
            "shortDescription": {"text": f.title},
        })  # fmt: skip
        location = {"artifactLocation": {"uri": f.file}}
        if f.line_start:
            location["region"] = {"startLine": f.line_start, "endLine": f.line_end or f.line_start}
        results.append({
            "ruleId": f"{f.tool}/{f.rule_id}",
            "level": SARIF_LEVELS[f.severity],
            "message": {"text": f.description or f.title},
            "locations": [{"physicalLocation": location}],
            # La huella estable permite a GitHub reconocer el mismo hallazgo entre escaneos.
            "partialFingerprints": {"secscan/v1": f.fingerprint},
        })  # fmt: skip
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "secscan", "rules": list(rules.values())}}, "results": results}],
    }
    return json.dumps(sarif, indent=2)


def print_table(result: ScanResult, console: Console) -> None:
    for alert in result.alerts:
        console.print(f"[bold white on red] ALERTA [/] [red]Contenido sospechoso en el repo escaneado: {escape(alert)}[/]")
    if result.hostile_hits:
        hits, more = shown_hits(result)
        table = Table(title="Fragmentos a revisar", title_justify="left")
        for column in ("Dónde", "Campo", "Tipo", "Fragmento"):
            table.add_column(column, overflow="fold")
        for hit in hits:
            # Sin escapar, Rich interpretaría «[red]…» del fragmento como marcado.
            table.add_row(escape(hit.where), escape(hit.field), escape(hit.kind), escape(hit.fragment))
        console.print(table)
        if more:
            console.print(f"… y {more} más (están todas en el informe JSON)")
        console.print()
    if result.findings:
        table = Table(show_lines=False)
        for column in ("Severidad", "Herramienta", "Regla", "Ubicación", "Título"):
            # fold: si no cabe, parte la línea en vez de cortarla con «…» (la ruta completa importa).
            table.add_column(column, overflow="fold")
        for f in result.findings:
            where = f.file + (f":{f.line_start}" if f.line_start else "")
            # Todo lo que viene del repo escaneado se escapa: Rich interpretaría «[red]…» como marcado.
            table.add_row(
                f"[{COLORS[f.severity]}]{f.severity.name}[/]", f.tool, escape(f.rule_id), escape(where), escape(f.title),
            )  # fmt: skip
        console.print(table)

    # Cobertura: qué se miró. Sin esto, "0 hallazgos" no distingue limpio de no analizado.
    for tool, targets in result.scanned.items():
        shown = ", ".join(targets) if 0 < len(targets) <= 4 else f"{len(targets)} objetivos"
        console.print(f"[green]✓[/] {escape(tool)}: analizado ({escape(shown)})")
    for tool, error in result.errors.items():
        console.print(f"[bold red]✗[/] {escape(tool)}: {escape(error)}")
    for warning in result.warnings:
        console.print(f"[yellow]![/] {escape(warning)}")

    counts = {s: sum(f.severity == s for f in result.findings) for s in Severity}
    summary = ", ".join(f"{n} {s.name.lower()}" for s, n in sorted(counts.items(), reverse=True) if n)
    console.print(f"\n{len(result.findings)} hallazgos" + (f" ({summary})" if summary else ""), end="")
    console.print(f" · {result.suppressed} ignorados" if result.suppressed else "")
