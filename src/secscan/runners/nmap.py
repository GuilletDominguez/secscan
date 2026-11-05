"""Nmap: puertos TCP abiertos de un host y qué servicio hay detrás.

Es un escaneo de conexión (`-sT`): no necesita privilegios y completa el saludo TCP de cada puerto. Sin `-sV`
no envía nada más; con `--versions` sí envía sondas para identificar el servicio y su versión.
"""

import ipaddress
import xml.etree.ElementTree as ET
from pathlib import Path

from secscan.models import Category, Finding, Severity
from secscan.runners.base import Runner, RunnerError, RunnerOutput, read_report
from secscan.targets import HostTarget

# Servicios que casi nunca deberían estar abiertos a internet: bases de datos, administración remota, protocolos
# sin cifrar. El resto de puertos abiertos solo informan (INFO).
RISKY_PORTS = {
    2375: ("Docker sin TLS", Severity.CRITICAL),
    23: ("Telnet", Severity.HIGH),
    445: ("SMB", Severity.HIGH),
    3389: ("RDP", Severity.HIGH),
    5900: ("VNC", Severity.HIGH),
    6379: ("Redis", Severity.HIGH),
    9200: ("Elasticsearch", Severity.HIGH),
    11211: ("Memcached", Severity.HIGH),
    27017: ("MongoDB", Severity.HIGH),
    1433: ("SQL Server", Severity.MEDIUM),
    3306: ("MySQL", Severity.MEDIUM),
    5432: ("PostgreSQL", Severity.MEDIUM),
    21: ("FTP", Severity.MEDIUM),
}
MAX_TEXT = 200


def _clip(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= MAX_TEXT else text[: MAX_TEXT - 1].rstrip() + "…"


def parse_nmap(xml_text: str) -> RunnerOutput:
    """Convierte el XML de nmap. Un hallazgo por puerto abierto; el puerto cerrado o filtrado no se lista."""
    # El XML de nmap no declara entidades. Si aparece alguna, no es de nmap: se rechaza antes de interpretarlo
    # (evita que una entrada con entidades anidadas agote la memoria).
    if "<!ENTITY" in xml_text:
        raise RunnerError("informe de nmap con entidades XML: no se interpreta")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as error:
        raise RunnerError(f"informe de nmap ilegible: {error}") from None

    findings, scanned = [], []
    for host in root.iter("host"):
        address = next(
            (a.get("addr", "") for a in host.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), ""
        )
        if not address:
            continue
        scanned.append(address)
        for port in host.iterfind("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            number, proto = int(port.get("portid", "0")), port.get("protocol", "tcp")
            service = port.find("service")
            name = service.get("name", "") if service is not None else ""
            banner = _clip(
                " ".join(service.get(key, "") for key in ("product", "version", "extrainfo"))
            ) if service is not None else ""
            risky = RISKY_PORTS.get(number)
            if risky:
                label, severity, rule = risky[0], risky[1], "exposed-service"
                title = f"{label} expuesto en el puerto {number}/{proto}"
                advice = "Cierra el puerto en el cortafuegos o limítalo a las IP que lo necesitan."
            else:
                severity, rule = Severity.INFO, "open-port"
                title = f"Puerto {number}/{proto} abierto" + (f" ({_clip(name)})" if name else "")
                advice = ""
            description = " ".join(part for part in (f"Servicio: {banner}." if banner else "", advice) if part)
            findings.append(
                Finding(
                    tool="nmap",
                    rule_id=rule,
                    title=title,
                    description=description,
                    severity=severity,
                    category=Category.NETWORK,
                    file=f"{address}:{number}/{proto}",  # identidad estable: la versión del servicio no entra
                )
            )
    if not scanned:
        # Nunca «limpio» sin haber mirado nada.
        raise RunnerError("nmap no devolvió ningún host")
    return RunnerOutput(findings=findings, scanned=scanned)


class NmapRunner(Runner):
    name = "nmap"
    image = "instrumentisto/nmap:latest"
    # El XML se escribe en /out; el entrypoint de la imagen ya es `nmap`.

    def __init__(self, target: HostTarget, ports: str | None = None, versions: bool = False):
        self.host = target
        self.ports = ports
        self.versions = versions
        # Un destino local solo es alcanzable desde la red del host.
        self.network = "host" if target.loopback else None
        self.timeout_seconds = 1200

    def _ips(self) -> list[str]:
        """Nmap no mezcla IPv4 e IPv6 en una ejecución: se prefiere IPv4 y solo hay IPv6 si no hay otra cosa."""
        v4 = [ip for ip in self.host.ips if ipaddress.ip_address(ip).version == 4]
        return v4 or list(self.host.ips)

    def args(self) -> list[str]:
        ips = self._ips()
        return [
            "-sT", "-Pn", "-n",  # conexión TCP normal, sin ping previo ni DNS: se escanea justo lo validado
            "--host-timeout", "15m", "--max-retries", "2",
            *(["-6"] if ipaddress.ip_address(ips[0]).version == 6 else []),
            *(["-p", self.ports] if self.ports else []),
            *(["-sV"] if self.versions else []),
            "-oX", "/out/nmap.xml",
            "--",  # lo siguiente nunca se lee como opción
            *ips,
        ]  # fmt: skip

    def run(self, target: Path | None = None) -> RunnerOutput:
        return super().run(None)  # no hay nada del disco que montar

    def parse(self, out_dir: Path) -> RunnerOutput:
        return parse_nmap(read_report(out_dir, "nmap.xml"))
