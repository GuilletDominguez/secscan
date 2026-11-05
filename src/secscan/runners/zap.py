"""OWASP ZAP: rastreo más análisis PASIVO de una aplicación web en ejecución.

No ataca: solo rastrea los enlaces y examina las respuestas (cabeceras, cookies, formularios…).
El escaneo activo, que sí envía ataques, no está implementado a propósito.
"""

import html
import json
import re
from urllib.parse import urlsplit
from pathlib import Path

import yaml

from secscan.models import Category, Finding, Severity
from secscan.runners.base import Runner, RunnerError, RunnerOutput, read_report
from secscan.targets import WebTarget

# riskcode de ZAP -> severidad. «Informational» (0) pasa a INFO.
RISK = {"3": Severity.HIGH, "2": Severity.MEDIUM, "1": Severity.LOW, "0": Severity.INFO}
LOW_CONFIDENCE = {"0", "1"}  # 0 = falso positivo marcado, 1 = baja
MAX_URLS = 5  # URL afectadas que se listan por alerta
MAX_TEXT = 500
_TAGS = re.compile(r"<[^>]+>")


def _text(fragment: str) -> str:
    """El HTML de ZAP (`<p>…</p>`) a texto plano."""
    plain = html.unescape(_TAGS.sub(" ", fragment.replace("</p>", " ")))
    plain = " ".join(plain.split())
    return plain if len(plain) <= MAX_TEXT else plain[: MAX_TEXT - 1].rstrip() + "…"


def _severity(alert: dict) -> Severity:
    severity = RISK.get(str(alert.get("riskcode")), Severity.INFO)
    if alert.get("confidence") in LOW_CONFIDENCE and severity > Severity.INFO:
        severity = Severity(severity - 1)  # misma regla que con Semgrep: confianza baja, un escalón menos
    return severity


def parse_zap(data: dict) -> RunnerOutput:
    """Convierte el JSON de ZAP. Un hallazgo por alerta y sitio, no por URL.

    Si cada URL fuera un hallazgo, la huella cambiaría cada vez que el rastreo encontrara otras
    páginas. Con (regla + sitio) la huella es estable y las URL afectadas van en la descripción.
    """
    findings, scanned = [], []
    for site in data.get("site", []):
        name = site["@name"]
        scanned.append(name)
        for alert in site.get("alerts", []):
            uris = sorted({instance["uri"] for instance in alert.get("instances", [])})
            where = ", ".join(uris[:MAX_URLS]) + (f" … y {len(uris) - MAX_URLS} más" if len(uris) > MAX_URLS else "")
            solution = _text(alert.get("solution", ""))
            cwe = alert.get("cweid", "")
            description = _text(alert.get("desc", ""))
            parts = [
                f"CWE-{cwe}" if cwe and cwe != "-1" else "",
                description,
                f"{len(uris)} URL afectada(s): {where}." if uris else "",
                f"Solución: {solution}" if solution else "",
            ]
            findings.append(
                Finding(
                    tool="zap",
                    rule_id=str(alert.get("alertRef") or alert.get("pluginid")),
                    title=alert.get("name") or alert.get("alert", "alerta de ZAP"),
                    description=" ".join(part for part in parts if part),
                    severity=_severity(alert),
                    category=Category.WEB,
                    file=name,  # el sitio: identidad estable de la alerta
                )
            )
    return RunnerOutput(findings=findings, scanned=scanned)


DEFAULT_PORTS = {"http": 80, "https": 443}


def scope_regex(url: str) -> str:
    """Expresión que acepta SOLO las URL del destino pedido (ZAP la aplica a la URL completa).

    Se construye con las partes de la URL ya analizadas y con un límite explícito detrás del host, del
    puerto y de la ruta. Un simple «url + .*» aceptaría también `https://mia.example.evil.com/`,
    `https://mia.example@evil.com/` (aquí `mia.example` es el usuario y el host real es evil.com) o
    el puerto `:12345` cuando el destino es `:1234`: una web hostil solo tendría que enlazarlas.
    """
    parts = urlsplit(url)
    scheme, host = parts.scheme, parts.hostname
    default = DEFAULT_PORTS[scheme]
    port = parts.port or default
    shown_host = f"[{host}]" if ":" in host else host  # IPv6
    # Esquema y host no distinguen mayúsculas; la ruta sí.
    authority = f"(?i:{re.escape(f'{scheme}://{shown_host}')})"
    # Con el puerto por defecto vale con o sin él; con otro, debe ser exactamente ese.
    port_part = f"(?::{port})?" if port == default else f":{port}"
    path = parts.path.rstrip("/")
    # Tras la ruta solo puede venir el final, «/», «?» o «#»: `/app` acepta `/app/x` pero no `/application`.
    return authority + port_part + re.escape(path) + r"(?:[/?#].*)?"


def context_url(url: str) -> str:
    """La URL del contexto, siempre terminada en «/».

    El Automation Framework añade cada URL del contexto como un PREFIJO (`url.*`) al alcance, además de
    nuestro `includePaths`. Sin la barra final, `http://127.0.0.1:1234` sería prefijo de
    `http://127.0.0.1:12345/…` y de `http://127.0.0.1:1234.evil.com/…`, y el rastreo los seguiría aunque la
    regex de `scope_regex` los excluya (comprobado con ZAP: el servidor del puerto 12345 recibía la petición).
    """
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}/"


def build_plan(url: str, minutes: int) -> dict:
    """Plan del Automation Framework: rastreo, análisis pasivo y informe JSON. Nada de ataques.

    El contexto limita el alcance a la URL pedida: ZAP no sigue enlaces ni redirecciones hacia otros
    sitios. Se escribe con yaml.safe_dump, así que la URL es siempre un dato y nunca YAML.
    """
    return {
        "env": {
            "contexts": [{"name": "secscan", "urls": [context_url(url)], "includePaths": [scope_regex(url)]}],
            "parameters": {"failOnError": True, "progressToStdout": False},
        },
        "jobs": [
            {"type": "passiveScan-config", "parameters": {"maxAlertsPerRule": 10}},
            # El contexto se indica explícitamente: el rastreo queda atado al alcance de arriba.
            {"type": "spider", "parameters": {"context": "secscan", "maxDuration": minutes, "url": url}},
            {"type": "passiveScan-wait", "parameters": {"maxDuration": 5}},
            {
                "type": "report",
                "parameters": {
                    "reportDir": "/zap/wrk/", "reportFile": "zap.json", "reportTitle": "secscan",
                    "template": "traditional-json",
                },
            },
        ],
    }  # fmt: skip


# Cadena fija (no lleva datos del usuario: la URL va en el plan). Dos fases, como el script oficial
# `zap-baseline.py`: instalar las reglas pasivas beta y ejecutar el plan.
#
# NO se usa `zap-baseline.py`: arranca ZAP con `-host 0.0.0.0` y la API sin clave (`api.disablekey=true`),
# así que con la red del host dejaba la API y un proxy abiertos en todas las interfaces durante el escaneo.
# Con `-cmd -autorun` y sin `-host`, ZAP solo escucha en loopback.
#
# El complemento OAST abre un servidor de «callbacks» en una dirección y puerto aleatorios de TODAS las
# interfaces (responde 200 vacío a cualquier cosa). No es la API ni un proxy, pero es un puerto accesible
# desde la red durante el escaneo: se limita a loopback con `oast.callback.localaddr`.
LOOPBACK_ONLY = "-config oast.callback.localaddr=127.0.0.1"
SCRIPT = (
    f"/zap/zap.sh -cmd {LOOPBACK_ONLY} -addonupdate -addoninstall pscanrulesBeta; "
    f"/zap/zap.sh -cmd {LOOPBACK_ONLY} -autorun /zap/wrk/plan.yaml"
)


class ZapRunner(Runner):
    name = "zap"
    image = "ghcr.io/zaproxy/zaproxy:stable"
    out_mount = "/zap/wrk"  # ZAP escribe sus informes en el directorio de trabajo
    entrypoint = "sh"

    def __init__(self, target: WebTarget, minutes: int = 1):
        self.web = target
        self.minutes = minutes
        # Un destino local solo es alcanzable desde la red del host. Para cualquier otro basta la de Docker.
        self.network = "host" if target.loopback else None
        # Arranque y descarga de reglas, el rastreo y la espera del análisis pasivo (hasta 5 min).
        self.timeout_seconds = minutes * 60 + 900

    def args(self) -> list[str]:
        return ["-c", SCRIPT]

    def prepare(self, out_dir: Path) -> None:
        (out_dir / "plan.yaml").write_text(yaml.safe_dump(build_plan(self.web.url, self.minutes)), encoding="utf-8")

    def extra_options(self) -> list[str]:
        # Las direcciones que se validaron se fijan dentro del contenedor: si el DNS cambiara después
        # (rebinding), ZAP seguiría yendo a lo comprobado y no a otra dirección.
        return [arg for ip in self.web.pinned_ips for arg in ("--add-host", f"{self.web.host}:{ip}")]

    def run(self, target: Path | None = None) -> RunnerOutput:
        return super().run(None)  # no hay nada del disco que montar

    def parse(self, out_dir: Path) -> RunnerOutput:
        try:
            return parse_zap(json.loads(read_report(out_dir, "zap.json")))
        except json.JSONDecodeError as error:
            raise RunnerError(f"informe de zap ilegible: {error}") from None
        except (KeyError, TypeError) as error:
            raise RunnerError(f"informe de zap con formato inesperado: {error}") from None
