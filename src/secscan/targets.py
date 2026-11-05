"""Validación de los destinos que se escanean (URL e imágenes) antes de lanzar ningún contenedor.

Un escaneo web envía tráfico a otro sistema. Estas comprobaciones evitan lo más grave: apuntar por
error (o por entrada maliciosa) a servicios internos o al metadata de la nube, y atacar algo ajeno
sin haberlo confirmado.
"""

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

# Nombre de imagen de Docker: empieza por letra o número (así nunca se lee como una opción `-x`)
# y solo lleva los caracteres que Docker admite en repositorio, etiqueta y digest.
IMAGE_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:/@+-]{0,254}$")


class TargetError(Exception):
    """El destino no es válido o no está permitido."""


@dataclass(frozen=True)
class WebTarget:
    url: str
    host: str
    loopback: bool  # True: el contenedor necesita la red del host para alcanzarlo
    # Direcciones ya validadas para un nombre de host: se fijan dentro del contenedor (--add-host) para que un
    # DNS que cambie después (rebinding) no desvíe el escaneo. Vacío si el destino ya es una IP literal.
    pinned_ips: tuple[str, ...] = ()


def _resolve(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise TargetError(f"no se pudo resolver el host «{host}»") from None
    addresses = []
    for info in infos:
        address = ipaddress.ip_address(info[4][0].split("%")[0])  # quita el scope de IPv6
        if address not in addresses:
            addresses.append(address)
    return addresses


def _vet_host(host: str, owns_target: bool) -> tuple[bool, bool, list[ipaddress.IPv4Address | ipaddress.IPv6Address]]:
    """Comprobaciones de dirección comunes a los escaneos web y de puertos.

    Devuelve (es loopback, es una IP literal, direcciones validadas).
    """
    addresses = _resolve(host)
    for address in addresses:
        if address.is_link_local or address.is_unspecified or address.is_multicast:
            raise TargetError(f"{address} es una dirección que no se escanea (enlace local, sin especificar o multicast)")

    loopback = all(address.is_loopback for address in addresses)
    if not loopback and any(address.is_loopback for address in addresses):
        raise TargetError(f"«{host}» resuelve a direcciones locales y externas a la vez")

    is_literal = _is_ip(host)
    # Libre de confirmación: lo que es local por definición (IP de loopback escrita tal cual, o `localhost`).
    # Un nombre cualquiera que hoy resuelve a loopback no lo es: su DNS lo controla otra persona.
    free = loopback and (is_literal or host.lower().rstrip(".") == "localhost")
    if not free and not owns_target:
        reason = "resuelve a una dirección local pero no es «localhost»" if loopback else "no es local"
        raise TargetError(
            f"«{host}» {reason}: confirma que es un sistema tuyo, o que tienes permiso para escanearlo, con --i-own-this"
        )
    return loopback, is_literal, addresses


def validate_web_target(url: str, owns_target: bool) -> WebTarget:
    """Valida la URL de un escaneo web.

    - Solo http/https, con host y sin credenciales ni fragmento.
    - Nunca enlace local (169.254.0.0/16, fe80::/10: ahí vive el metadata de la nube), ni
      direcciones sin especificar o multicast.
    - Solo una IP literal de loopback o el nombre exacto `localhost` se permiten sin confirmar. Cualquier
      otro nombre, aunque resuelva a loopback, exige `owns_target`: un DNS ajeno puede apuntar a 127.0.0.1
      hoy y a otra dirección después.
    - Para todo nombre de host (también `localhost`) se devuelven las direcciones validadas, que luego se
      fijan en el contenedor.
    """
    # urlsplit descarta en silencio tabuladores y saltos de línea, pero `url` se conservaría con ellos: se rechazan.
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in url):
        raise TargetError("la URL no puede llevar espacios ni caracteres de control")
    try:
        parts = urlsplit(url)
        host, _port = parts.hostname, parts.port  # .port lanza ValueError si es inválido
    except ValueError:
        raise TargetError("la URL no es válida") from None
    if parts.scheme not in ("http", "https"):
        raise TargetError("solo se admiten URL http:// o https://")
    if not host:
        raise TargetError("la URL no tiene host")
    if parts.username is not None or parts.password is not None:
        raise TargetError("la URL no puede llevar usuario ni contraseña (quedarían en los informes)")
    if parts.fragment:
        raise TargetError("la URL no puede llevar fragmento (#…)")

    loopback, is_literal, addresses = _vet_host(host, owns_target)

    return WebTarget(
        url=url,
        host=host,
        loopback=loopback,
        pinned_ips=() if is_literal else tuple(str(address) for address in addresses),
    )


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def validate_image_name(name: str) -> str:
    if not IMAGE_NAME.match(name):
        raise TargetError(
            "nombre de imagen no válido: debe empezar por letra o número y solo llevar letras, números y _ . : / @ + -"
        )
    return name


# Nombre de host o dominio tal cual: nada de esquema, puerto, ruta ni caracteres raros. Empieza por letra o número,
# así que nunca se lee como una opción `-x` de la herramienta.
HOSTNAME = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$")


@dataclass(frozen=True)
class HostTarget:
    host: str
    loopback: bool
    # Las direcciones ya validadas: es lo que se escanea, no el nombre, para que un DNS que cambie después
    # (rebinding) no desvíe el escaneo hacia otra máquina.
    ips: tuple[str, ...]


def validate_host_target(host: str, owns_target: bool) -> HostTarget:
    """Valida el host de un escaneo de puertos (un dominio o una IP, sin esquema ni puerto).

    Mismas reglas que `validate_web_target`: nunca enlace local, sin especificar ni multicast; solo loopback
    literal o `localhost` sin confirmar; todo lo demás exige `owns_target`.
    """
    if not host or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in host):
        raise TargetError("el host no puede estar vacío ni llevar espacios ni caracteres de control")
    if not _is_ip(host) and not HOSTNAME.match(host):
        raise TargetError("host no válido: escribe solo el dominio o la IP, sin http://, puerto ni ruta")
    loopback, _is_literal, addresses = _vet_host(host, owns_target)
    return HostTarget(host=host, loopback=loopback, ips=tuple(str(address) for address in addresses))


PORTS = re.compile(r"^[0-9]{1,5}(?:-[0-9]{1,5})?(?:,[0-9]{1,5}(?:-[0-9]{1,5})?){0,99}$")


def validate_ports(ports: str) -> str:
    """Lista de puertos al estilo nmap: `80,443` o `1-1024`. Nada más, y todos entre 1 y 65535."""
    if not PORTS.match(ports) or any(not 1 <= int(n) <= 65535 for n in re.findall(r"\d+", ports)):
        raise TargetError("puertos no válidos: usa números del 1 al 65535, separados por comas o en rango (p. ej. 80,443 o 1-1024)")
    return ports
