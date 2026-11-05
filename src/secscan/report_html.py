"""Informe HTML: un solo fichero, sin JavaScript ni recursos externos. Se abre en cualquier navegador."""

from html import escape as _escape
from importlib.metadata import PackageNotFoundError, version

from secscan.models import Finding, ScanResult, Severity
from secscan.report import LABELS, display_name, grouped, shown_hits

MAX_SNIPPET = 400
MAX_DESCRIPTION = 600

# Sin JavaScript, sin imágenes ni fuentes externas y sin permitir que el documento se incruste en otro.
# Defensa en profundidad: aunque se escapa todo, un fallo de escape no podría ejecutar scripts.
CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"

CSS = """
:root {
  --bg: #f7f7f5; --surface: #ffffff; --text: #1c1d1f; --muted: #5d6066; --line: #dfe0e3;
  --critical: #8f1d4e; --high: #b42318; --medium: #92580a; --low: #1d5fa8; --info: #5d6066;
  --critical-bg: #fbe9f1; --high-bg: #fdebea; --medium-bg: #fcf1dd; --low-bg: #e7f0fb; --info-bg: #eceef0;
  --ok: #1a6b3c; --ok-bg: #e3f4ea; --warn: #92580a; --warn-bg: #fcf1dd; --bad: #b42318; --bad-bg: #fdebea;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #131416; --surface: #1c1e21; --text: #e8e9ea; --muted: #a0a4ab; --line: #34373c;
    --critical: #f08ab8; --high: #ff8d83; --medium: #f1b560; --low: #7db2ee; --info: #a0a4ab;
    --critical-bg: #3a1828; --high-bg: #3d1c19; --medium-bg: #382a12; --low-bg: #172a40; --info-bg: #2a2c30;
    --ok: #6fd29a; --ok-bg: #153023; --warn: #f1b560; --warn-bg: #382a12; --bad: #ff8d83; --bad-bg: #3d1c19;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 960px; margin: 0 auto; padding: 24px 16px 48px; }
h1 { font-size: 1.6rem; margin: 0 0 4px; }
h2 { font-size: 1.15rem; margin: 32px 0 12px; }
.meta { color: var(--muted); font-size: .9rem; margin: 0; }
code, .mono { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; font-size: .85em; }
.banner { margin: 20px 0 0; padding: 12px 16px; border-radius: 8px; border: 1px solid var(--line); }
.banner.ok { background: var(--ok-bg); color: var(--ok); }
.banner.warn { background: var(--warn-bg); color: var(--warn); }
.banner.bad { background: var(--bad-bg); color: var(--bad); }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 12px; margin: 20px 0 0; }
.tile { background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 12px 16px; border-top: 4px solid var(--c, var(--line)); }
.tile .n { font-size: 1.8rem; font-weight: 700; line-height: 1.1; }
.tile .l { color: var(--muted); font-size: .85rem; }
.bar { display: flex; height: 10px; border-radius: 5px; overflow: hidden; background: var(--line); margin: 16px 0 0; }
.bar span { background: var(--c); }
.sev-critical { --c: var(--critical); --bg2: var(--critical-bg); } .sev-high { --c: var(--high); --bg2: var(--high-bg); }
.sev-medium { --c: var(--medium); --bg2: var(--medium-bg); } .sev-low { --c: var(--low); --bg2: var(--low-bg); }
.sev-info { --c: var(--info); --bg2: var(--info-bg); }
details.group { margin: 12px 0; }
details.group > summary { cursor: pointer; font-weight: 600; padding: 8px 0; color: var(--c); }
.card { background: var(--surface); border: 1px solid var(--line); border-left: 4px solid var(--c); border-radius: 8px; padding: 12px 16px; margin: 8px 0; }
.card h3 { font-size: 1rem; margin: 0 0 4px; overflow-wrap: anywhere; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 10px; background: var(--bg2); color: var(--c); font-size: .75rem; font-weight: 700; margin-right: 6px; }
.card .where, .card .ids { color: var(--muted); font-size: .85rem; overflow-wrap: anywhere; margin: 2px 0; }
.card p { margin: 8px 0 0; overflow-wrap: anywhere; }
pre { margin: 8px 0 0; padding: 8px 12px; background: var(--bg); border: 1px solid var(--line); border-radius: 6px; overflow-x: auto; white-space: pre-wrap; overflow-wrap: anywhere; }
ul.plain { list-style: none; padding: 0; margin: 0; }
ul.plain li { padding: 6px 0; border-bottom: 1px solid var(--line); overflow-wrap: anywhere; }
.yes { color: var(--ok); font-weight: 700; } .no { color: var(--bad); font-weight: 700; } .attn { color: var(--warn); font-weight: 700; }
.hits { margin-top: 12px; color: var(--text); } .hits summary { cursor: pointer; font-weight: 600; }
.banner pre { background: var(--surface); }
footer { margin-top: 40px; color: var(--muted); font-size: .85rem; }
"""


def esc(value: object) -> str:
    """Escapa todo lo que viene del repo escaneado: es entrada no confiable."""
    return _escape(str(value), quote=True)


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


def _where(finding: Finding) -> str:
    return finding.file + (f":{finding.line_start}" if finding.line_start else "")


def _card(finding: Finding) -> str:
    css = f"sev-{finding.severity.name.lower()}"
    parts = [
        f'<article class="card {css}">',
        f'<h3><span class="badge">{esc(LABELS[finding.severity])}</span>{esc(finding.title)}</h3>',
        f'<p class="where mono">{esc(_where(finding))}</p>',
        f'<p class="ids">{esc(finding.tool)} · {esc(finding.rule_id)} · huella <code>{esc(finding.fingerprint)}</code></p>',
    ]
    if finding.description:
        parts.append(f"<p>{esc(_cut(finding.description, MAX_DESCRIPTION))}</p>")
    if finding.snippet:
        parts.append(f"<pre><code>{esc(_cut(finding.snippet, MAX_SNIPPET))}</code></pre>")
    parts.append("</article>")
    return "".join(parts)


def _hits(result: ScanResult) -> str:
    if not result.hostile_hits:
        return ""
    hits, more = shown_hits(result)
    # El fragmento va dentro de <code> y escapado: se ve el texto, nunca se interpreta.
    items = "".join(
        f"<li><span class=\"mono\">{esc(hit.where)}</span> · {esc(hit.field)} · {esc(hit.kind)}"
        f"<pre><code>{esc(hit.fragment)}</code></pre></li>"
        for hit in hits
    )
    tail = f'<li class="meta">… y {more} más (están todas en el informe JSON)</li>' if more else ""
    return f'<details class="hits" open><summary>Fragmentos a revisar ({len(result.hostile_hits)})</summary><ul class="plain">{items}{tail}</ul></details>'


def _alerts(result: ScanResult) -> str:
    return "".join(
        f'<div class="banner bad" role="alert"><strong>Contenido sospechoso en el repo escaneado.</strong> {esc(alert)}'
        f"{_hits(result) if index == 0 else ''}</div>"
        for index, alert in enumerate(result.alerts)
    )


def _banner(result: ScanResult) -> str:
    if result.errors:
        failed = ", ".join(esc(tool) for tool in result.errors)
        return (
            f'<div class="banner bad" role="alert"><strong>Escaneo incompleto.</strong> Fallaron: {failed}. '
            "Un resultado sin hallazgos no significa «limpio».</div>"
        )
    if not result.findings:
        return '<div class="banner ok"><strong>Sin hallazgos.</strong></div>'
    return ""


def _tiles(result: ScanResult) -> str:
    counts = {severity: len(found) for severity, found in grouped(result)}
    tiles = [f'<div class="tile"><div class="n">{len(result.findings)}</div><div class="l">Total</div></div>']
    for severity in sorted(Severity, reverse=True):
        css = f"sev-{severity.name.lower()}"
        tiles.append(f'<div class="tile {css}"><div class="n">{counts.get(severity, 0)}</div><div class="l">{esc(LABELS[severity])}</div></div>')
    bar = ""
    if result.findings:
        segments = "".join(
            f'<span class="sev-{s.name.lower()}" style="width:{100 * n / len(result.findings):.2f}%" title="{esc(LABELS[s])}: {n}"></span>'
            for s, n in sorted(counts.items(), reverse=True)
        )
        bar = f'<div class="bar" role="img" aria-label="Reparto de hallazgos por severidad">{segments}</div>'
    return f'<div class="tiles">{"".join(tiles)}</div>{bar}'


def _coverage(result: ScanResult) -> str:
    items = []
    for tool, targets in result.scanned.items():
        shown = ", ".join(esc(t) for t in targets) if 0 < len(targets) <= 4 else f"{len(targets)} objetivos"
        items.append(f'<li><span class="yes">✓</span> {esc(tool)}: analizado ({shown})</li>')
    for tool, error in result.errors.items():
        items.append(f'<li><span class="no">✗</span> {esc(tool)}: {esc(error)}</li>')
    for warning in result.warnings:
        items.append(f'<li><span class="attn">!</span> {esc(warning)}</li>')
    return f'<ul class="plain">{"".join(items)}</ul>' if items else "<p class=\"meta\">Sin datos de cobertura.</p>"


def to_html(result: ScanResult) -> str:
    try:
        tool_version = version("secscan")
    except PackageNotFoundError:
        tool_version = "dev"
    name = esc(display_name(result))
    meta = " · ".join(
        part
        for part in (
            f"Generado: {esc(result.scanned_at)}" if result.scanned_at else "",
            "Herramientas: " + ", ".join(esc(t) for t in result.scanned) if result.scanned else "",
            f"{result.suppressed} ignorados por .secscan.yml" if result.suppressed else "",
        )
        if part
    )
    groups = "".join(
        f'<details class="group sev-{severity.name.lower()}"{" open" if severity >= Severity.HIGH else ""}>'
        f"<summary>{esc(LABELS[severity])} ({len(found)})</summary>{''.join(_card(f) for f in found)}</details>"
        for severity, found in grouped(result)
    )
    findings = f"<h2>Hallazgos</h2>{groups}" if groups else ""
    signature = f"Informe firmado por <strong>{esc(result.signed_by)}</strong>. " if result.signed_by else ""
    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{CSP}">
<title>secscan · {name}</title>
<style>{CSS}</style>
</head>
<body>
<main>
<h1>Informe de seguridad · {name}</h1>
<p class="meta">{meta}</p>
{_alerts(result)}
{_banner(result)}
{_tiles(result)}
{findings}
<h2>Cobertura</h2>
{_coverage(result)}
<footer>{signature}Generado con secscan {esc(tool_version)}. La huella de cada hallazgo sirve para ignorarlo en <code>.secscan.yml</code>.</footer>
</main>
</body>
</html>
"""
