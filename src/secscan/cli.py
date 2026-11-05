"""Línea de comandos: `secscan scan <ruta>`."""

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape

from secscan import report
from secscan.report_html import to_html
from secscan.report_md import to_markdown
from secscan.config import Config, ConfigError, load_config, load_config_file
from secscan.models import Severity
from secscan.scanner import RUNNERS, scan, scan_image, scan_web
from secscan.targets import TargetError, validate_image_name, validate_web_target

app = typer.Typer(help="Escáner de seguridad: secretos, código, librerías y configuración.", no_args_is_help=True)
# La salida de datos (json/sarif) va a stdout; los mensajes de estado, a stderr.
err = Console(stderr=True)


class Format(StrEnum):
    table = "table"
    json = "json"
    sarif = "sarif"
    md = "md"
    html = "html"


# Formatos que producen un texto completo. La tabla es aparte: se pinta con colores en la terminal.
RENDERERS = {
    Format.json: report.to_json,
    Format.sarif: report.to_sarif,
    Format.md: to_markdown,
    Format.html: to_html,
}
# Dentro de la carpeta de informes: git la ignora entera (como hacen pytest o ruff con sus cachés). Así los informes,
# que contienen hallazgos del repo analizado, no acaban en un `git add .`, y secscan no toca ningún fichero del repo.
REPORT_DIR_GITIGNORE = "# Creado por secscan: los informes contienen hallazgos y no deben subirse.\n*\n"
REPORT_FILES = {
    "secscan-report.html": to_html,
    "secscan-report.md": to_markdown,
    "secscan-report.json": report.to_json,
    "secscan-report.sarif": report.to_sarif,  # el que sube la GitHub Action a la pestaña de seguridad
}


class FailOn(StrEnum):
    none = "none"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


FormatOpt = Annotated[Format, typer.Option("--format", help="Formato de salida.")]
OutputOpt = Annotated[Path | None, typer.Option("--output", "-o", help="Fichero de salida (por defecto, stdout).")]
FailOnOpt = Annotated[FailOn, typer.Option(help="Sale con código 1 si hay hallazgos de esta severidad o más.")]
ReportDirOpt = Annotated[Path | None, typer.Option(help="Carpeta donde escribir los informes HTML, Markdown y JSON a la vez.")]
ConfigOpt = Annotated[
    Path | None,
    typer.Option("--config", exists=True, dir_okay=False, resolve_path=True, help="Fichero .secscan.yml con lo que se ignora."),
]


SignedByOpt = Annotated[
    str,
    typer.Option("--signed-by", help="Quién firma el informe (aparece en el HTML y el Markdown). Por defecto, nadie."),
]
MAX_SIGNATURE = 100


def _signature(value: str) -> str:
    """La firma la decide quien ejecuta secscan: ni se rellena sola ni lleva saltos de línea ni caracteres de control."""
    value = value.strip()
    if len(value) > MAX_SIGNATURE or any(ord(char) < 32 or ord(char) == 127 for char in value):
        err.print(f"[red]--signed-by: como mucho {MAX_SIGNATURE} caracteres y sin saltos de línea ni caracteres de control[/]")
        raise typer.Exit(2)
    return value


def _config_from(path: Path | None) -> Config:
    try:
        return load_config_file(path) if path else Config()
    except ConfigError as error:
        err.print(f"[red]{escape(str(error))}[/]")
        raise typer.Exit(2) from None


def _emit(
    result, output_format: Format, output: Path | None, report_dir: Path | None, fail_on: FailOn, signed_by: str = ""
) -> None:
    """Salida común a todos los comandos: formato, ficheros, informes y código de salida."""
    result.signed_by = _signature(signed_by)
    to_terminal = output_format is Format.table and output is None
    if to_terminal:
        report.print_table(result, Console())
    elif output_format is Format.table:  # tabla a un fichero: sin colores
        with output.open("w", encoding="utf-8") as handle:
            report.print_table(result, Console(file=handle, no_color=True, width=140))
    else:
        text = RENDERERS[output_format](result)
        if output:
            output.write_text(text, encoding="utf-8")
        else:
            typer.echo(text)
    if output:
        err.print(f"Informe escrito en {escape(str(output))}")

    if report_dir:
        report_dir.mkdir(parents=True, exist_ok=True)
        ignore = report_dir / ".gitignore"
        if not ignore.exists():  # si ya hay uno (de otra ejecución, o puesto por la persona), no se pisa
            ignore.write_text(REPORT_DIR_GITIGNORE, encoding="utf-8")
        for filename, render in REPORT_FILES.items():
            (report_dir / filename).write_text(render(result), encoding="utf-8")
        err.print(f"Informes escritos en {escape(str(report_dir))}: {', '.join(REPORT_FILES)}")

    if not to_terminal:  # en la terminal la tabla ya incluye errores y avisos
        for tool, error in result.errors.items():
            err.print(f"[bold red]✗[/] {escape(tool)}: {escape(error)}")
        for warning in result.warnings:
            err.print(f"[yellow]![/] {escape(warning)}")

    worst = result.max_severity()
    if fail_on is not FailOn.none and worst is not None and worst >= Severity.parse(fail_on):
        raise typer.Exit(1)
    if result.errors:
        raise typer.Exit(2)


@app.callback()
def main() -> None:
    """Escáner de seguridad unificado."""


@app.command("scan")
def scan_command(
    path: Annotated[Path, typer.Argument(exists=True, file_okay=False, resolve_path=True, help="Repo a escanear.")],
    tools: Annotated[str, typer.Option(help="Herramientas separadas por comas.")] = ",".join(RUNNERS),
    output_format: FormatOpt = Format.table,
    output: OutputOpt = None,
    fail_on: FailOnOpt = FailOn.high,
    report_dir: ReportDirOpt = None,
    signed_by: SignedByOpt = "",
    history: Annotated[bool, typer.Option("--history", help="Gitleaks revisa también todos los commits (más lento).")] = False,
) -> None:
    selected = [name.strip() for name in tools.split(",") if name.strip()]
    unknown = [name for name in selected if name not in RUNNERS]
    if unknown:
        err.print(f"[red]Herramientas desconocidas:[/] {escape(', '.join(unknown))}. Disponibles: {', '.join(RUNNERS)}")
        raise typer.Exit(2)

    try:
        config = load_config(path)
    except ConfigError as error:
        err.print(f"[red]{escape(str(error))}[/]")
        raise typer.Exit(2) from None

    err.print(f"Escaneando {escape(str(path))} con {', '.join(selected)}…")
    result = scan(path, selected, config, history=history)

    _emit(result, output_format, output, report_dir, fail_on, signed_by)


@app.command("web")
def web_command(
    url: Annotated[str, typer.Argument(help="URL de la aplicación (http:// o https://).")],
    i_own_this: Annotated[
        bool, typer.Option("--i-own-this", help="Confirma que el sistema es tuyo o tienes permiso para escanearlo (obligatorio si no es localhost).")
    ] = False,
    minutes: Annotated[int, typer.Option(min=1, max=30, help="Minutos máximos de rastreo.")] = 1,
    config: ConfigOpt = None,
    output_format: FormatOpt = Format.table,
    output: OutputOpt = None,
    fail_on: FailOnOpt = FailOn.high,
    report_dir: ReportDirOpt = None,
    signed_by: SignedByOpt = "",
) -> None:
    """Escaneo web PASIVO con OWASP ZAP: rastrea y examina las respuestas, sin enviar ataques."""
    try:
        target = validate_web_target(url, i_own_this)
    except TargetError as error:
        err.print(f"[red]{escape(str(error))}[/]")
        raise typer.Exit(2) from None
    cfg = _config_from(config)

    err.print(f"Escaneando {escape(url)} con ZAP (rastreo y análisis pasivo, hasta {minutes} min)…")
    _emit(scan_web(target, cfg, minutes), output_format, output, report_dir, fail_on, signed_by)


@app.command("image")
def image_command(
    image: Annotated[str, typer.Argument(help="Imagen de Docker que ya esté en local, p. ej. mi-app:1.0.")],
    config: ConfigOpt = None,
    output_format: FormatOpt = Format.table,
    output: OutputOpt = None,
    fail_on: FailOnOpt = FailOn.high,
    report_dir: ReportDirOpt = None,
    signed_by: SignedByOpt = "",
) -> None:
    """Escanea una imagen de contenedor: paquetes del sistema, dependencias y secretos en las capas."""
    try:
        validate_image_name(image)
    except TargetError as error:
        err.print(f"[red]{escape(str(error))}[/]")
        raise typer.Exit(2) from None
    cfg = _config_from(config)

    err.print(f"Escaneando la imagen {escape(image)} con Trivy…")
    _emit(scan_image(image, cfg), output_format, output, report_dir, fail_on, signed_by)
