"""Escaneo de puertos (nmap): parser, validación del host y de los puertos, y comando."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from secscan import cli
from secscan.models import Category, ScanResult, Severity
from secscan.runners.base import RunnerError
from secscan.runners.nmap import NmapRunner, parse_nmap
from secscan.targets import HostTarget, TargetError, validate_host_target, validate_ports

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_xml():
    return (FIXTURES / "nmap.xml").read_text()


class TestParser:
    def test_one_finding_per_open_port_only(self):
        out = parse_nmap(fixture_xml())
        assert [f.file for f in out.findings] == [
            "203.0.113.7:22/tcp", "203.0.113.7:80/tcp", "203.0.113.7:3306/tcp", "203.0.113.7:6379/tcp",
        ]  # fmt: skip
        assert out.scanned == ["203.0.113.7"]  # el puerto cerrado y el filtrado no salen

    def test_risky_services_are_graded_and_the_rest_is_info(self):
        by_port = {f.file.split(":")[1]: f for f in parse_nmap(fixture_xml()).findings}
        assert by_port["6379/tcp"].severity is Severity.HIGH
        assert by_port["3306/tcp"].severity is Severity.MEDIUM
        assert by_port["3306/tcp"].rule_id == "exposed-service"
        assert by_port["22/tcp"].severity is Severity.INFO
        assert by_port["22/tcp"].rule_id == "open-port"
        assert all(f.category is Category.NETWORK and f.tool == "nmap" for f in by_port.values())

    def test_banner_goes_in_the_description_and_not_in_the_fingerprint(self):
        ssh = parse_nmap(fixture_xml()).findings[0]
        assert "OpenSSH 9.6" in ssh.description
        newer = parse_nmap(fixture_xml().replace('version="9.6"', 'version="9.7"')).findings[0]
        assert newer.fingerprint == ssh.fingerprint  # actualizar el servicio no reabre un hallazgo ignorado

    def test_no_host_is_an_error_never_a_clean_result(self):
        with pytest.raises(RunnerError, match="ningún host"):
            parse_nmap('<?xml version="1.0"?><nmaprun></nmaprun>')

    def test_garbage_and_entities_are_rejected(self):
        with pytest.raises(RunnerError, match="ilegible"):
            parse_nmap("esto no es xml")
        with pytest.raises(RunnerError, match="entidades"):
            parse_nmap('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><nmaprun>&a;</nmaprun>')


class TestTarget:
    def test_loopback_is_free_and_anything_else_needs_confirmation(self):
        assert validate_host_target("127.0.0.1", False).loopback
        assert validate_host_target("localhost", False).ips
        with pytest.raises(TargetError, match="--i-own-this"):
            validate_host_target("203.0.113.7", False)
        assert validate_host_target("203.0.113.7", True).ips == ("203.0.113.7",)

    @pytest.mark.parametrize("ip", ["169.254.169.254", "0.0.0.0", "224.0.0.1", "fe80::1"])
    def test_never_scans_link_local_unspecified_or_multicast(self, ip):
        with pytest.raises(TargetError, match="no se escanea"):
            validate_host_target(ip, True)

    @pytest.mark.parametrize(
        "bad", ["", "-sS", "--script=x", "http://example.com", "example.com:22", "example.com/x", "a b", "a;b", "a\nb", "ejemplo.com."]
    )  # fmt: skip
    def test_rejects_things_that_are_not_a_plain_host(self, bad):
        with pytest.raises(TargetError):
            validate_host_target(bad, True)

    @pytest.mark.parametrize("ports", ["80", "80,443", "1-1024", "22,80-90,443"])
    def test_valid_ports(self, ports):
        assert validate_ports(ports) == ports

    @pytest.mark.parametrize("ports", ["", "0", "65536", "80;ls", "-p-", "80,", "a", "1-2-3", "--script=x"])
    def test_invalid_ports(self, ports):
        with pytest.raises(TargetError):
            validate_ports(ports)


class TestRunner:
    def test_args_end_options_before_the_addresses(self):
        args = NmapRunner(HostTarget("example.com", False, ("203.0.113.7", "2001:db8::1")), "80,443", True).args()
        assert args[-2:] == ["--", "203.0.113.7"]  # solo IPv4 si la hay; nmap no mezcla familias
        assert "-sT" in args and "-sV" in args and args[args.index("-p") + 1] == "80,443"
        assert "-6" not in args

    def test_ipv6_only_target_uses_dash_6(self):
        args = NmapRunner(HostTarget("v6.example", False, ("2001:db8::1",))).args()
        assert "-6" in args and args[-1] == "2001:db8::1"
        assert "-sV" not in args and "-p" not in args

    def test_loopback_uses_the_host_network_and_others_the_default(self):
        assert NmapRunner(HostTarget("localhost", True, ("127.0.0.1",))).network == "host"
        assert NmapRunner(HostTarget("example.com", False, ("203.0.113.7",))).network is None


class TestCommand:
    runner = CliRunner()

    def test_refuses_a_remote_host_without_confirmation_before_running_anything(self, monkeypatch):
        monkeypatch.setattr(cli, "scan_ports", lambda *a, **k: pytest.fail("no debe escanear"))
        result = self.runner.invoke(cli.app, ["ports", "203.0.113.7"])
        assert result.exit_code == 2

    def test_bad_ports_exit_2(self, monkeypatch):
        monkeypatch.setattr(cli, "scan_ports", lambda *a, **k: pytest.fail("no debe escanear"))
        assert self.runner.invoke(cli.app, ["ports", "127.0.0.1", "--ports", "80;ls"]).exit_code == 2

    def test_passes_options_through(self, monkeypatch):
        seen = {}

        def fake(target, config, ports, versions):
            seen.update(host=target.host, ports=ports, versions=versions)
            return ScanResult(target=target.host)

        monkeypatch.setattr(cli, "scan_ports", fake)
        result = self.runner.invoke(cli.app, ["ports", "127.0.0.1", "--ports", "80,443", "--versions", "--fail-on", "none"])
        assert result.exit_code == 0, result.output
        assert seen == {"host": "127.0.0.1", "ports": "80,443", "versions": True}
