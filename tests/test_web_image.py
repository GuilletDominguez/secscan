"""Escaneo web (ZAP) y de imágenes (Trivy): protecciones del destino, parsers y comandos de Docker."""

import json
import re
import socket
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secscan import cli
from secscan.config import Config
from secscan.hostile import find_hostile_content
from secscan.models import Category, ScanResult, Severity
from secscan.report_html import to_html
from secscan.runners.base import RunnerError
from secscan.runners.trivy import TrivyImageRunner, parse_trivy_image
from secscan.runners.zap import ZapRunner, context_url, parse_zap, scope_regex
from secscan.targets import TargetError, WebTarget, validate_image_name, validate_web_target

FIXTURES = Path(__file__).parent / "fixtures"


def load(name):
    return json.loads((FIXTURES / name).read_text())


def resolving(monkeypatch, mapping):
    """Resuelve nombres sin tocar la red: {host: [ip, ...]}."""

    def fake(host, *args, **kwargs):
        if host not in mapping:
            raise socket.gaierror("sin resolver")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in mapping[host]]

    monkeypatch.setattr(socket, "getaddrinfo", fake)


class TestWebTargetGuards:
    def test_loopback_needs_no_confirmation_and_uses_the_host_network(self):
        for url in ("http://127.0.0.1:8000", "http://[::1]:8000/app", "http://127.1.2.3/"):
            target = validate_web_target(url, owns_target=False)
            assert target.loopback and target.pinned_ips == ()  # una IP literal no necesita fijarse

    def test_localhost_by_name_counts_as_loopback_and_its_addresses_are_still_pinned(self, monkeypatch):
        resolving(monkeypatch, {"localhost": ["127.0.0.1", "::1"]})
        target = validate_web_target("http://localhost:3000", False)

        assert target.loopback and target.pinned_ips == ("127.0.0.1", "::1")  # todas, para v4 y v6

    def test_localhost_is_recognised_whatever_its_case_or_trailing_dot(self, monkeypatch):
        resolving(monkeypatch, {"localhost": ["127.0.0.1"], "localhost.": ["127.0.0.1"]})  # urlsplit pasa el host a minúsculas
        assert validate_web_target("http://LocalHost:3000", False).loopback
        assert validate_web_target("http://localhost.:3000", False).loopback

    def test_another_name_that_resolves_to_loopback_is_not_free(self, monkeypatch):
        # Un DNS ajeno puede apuntar a 127.0.0.1 hoy y a otra dirección (p. ej. el metadata de la nube) después.
        resolving(monkeypatch, {"127.0.0.1.nip.example": ["127.0.0.1"], "evil.example": ["127.0.0.1"]})

        for host in ("127.0.0.1.nip.example", "evil.example"):
            with pytest.raises(TargetError, match="no es «localhost»"):
                validate_web_target(f"http://{host}/", owns_target=False)

    def test_with_the_flag_that_name_is_allowed_but_still_pinned(self, monkeypatch):
        resolving(monkeypatch, {"evil.example": ["127.0.0.1"]})
        target = validate_web_target("http://evil.example:8000/", owns_target=True)

        assert target.loopback and target.pinned_ips == ("127.0.0.1",)

    def test_anything_else_requires_the_ownership_flag(self):
        with pytest.raises(TargetError, match="--i-own-this"):
            validate_web_target("http://93.184.216.34", owns_target=False)
        assert not validate_web_target("http://93.184.216.34", owns_target=True).loopback

    def test_private_ranges_are_not_free_either(self):
        for ip in ("10.0.0.5", "192.168.1.10", "172.16.0.1"):
            with pytest.raises(TargetError, match="--i-own-this"):
                validate_web_target(f"http://{ip}/", owns_target=False)

    @pytest.mark.parametrize("ip", ["169.254.169.254", "169.254.0.1", "[fe80::1]", "0.0.0.0", "224.0.0.1"])
    def test_link_local_unspecified_and_multicast_are_never_scanned_even_with_the_flag(self, ip):
        with pytest.raises(TargetError, match="no se escanea"):
            validate_web_target(f"http://{ip}/latest", owns_target=True)

    def test_a_name_that_resolves_to_the_cloud_metadata_address_is_refused(self, monkeypatch):
        resolving(monkeypatch, {"trampa.example": ["169.254.169.254"]})
        with pytest.raises(TargetError, match="no se escanea"):
            validate_web_target("http://trampa.example/", owns_target=True)

    def test_a_name_with_one_bad_address_among_good_ones_is_refused(self, monkeypatch):
        resolving(monkeypatch, {"mixto.example": ["93.184.216.34", "169.254.169.254"]})
        with pytest.raises(TargetError):
            validate_web_target("http://mixto.example/", owns_target=True)

    def test_a_name_mixing_loopback_and_external_is_refused(self, monkeypatch):
        resolving(monkeypatch, {"doble.example": ["127.0.0.1", "93.184.216.34"]})
        with pytest.raises(TargetError, match="locales y externas"):
            validate_web_target("http://doble.example/", owns_target=True)

    def test_the_validated_ip_is_pinned_for_names_but_not_for_literals(self, monkeypatch):
        resolving(monkeypatch, {"mia.example": ["93.184.216.34"]})
        assert validate_web_target("https://mia.example/", True).pinned_ips == ("93.184.216.34",)
        assert validate_web_target("https://93.184.216.34/", True).pinned_ips == ()

    @pytest.mark.parametrize(
        "url",
        ["http://127.0.0.1:8000/a b", "http://127.0.0.1:8000/\nhttp://evil", "http://127.0.0.1:8000/\tx", "http://127.0.0.1/\x00", " http://127.0.0.1/"],
    )
    def test_whitespace_and_control_characters_are_rejected_not_silently_dropped(self, url):
        with pytest.raises(TargetError, match="caracteres de control"):
            validate_web_target(url, owns_target=True)

    @pytest.mark.parametrize(
        "url, message",
        [
            ("file:///etc/passwd", "http"),
            ("ftp://host/", "http"),
            ("javascript:alert(1)", "http"),
            ("http://", "host"),
            ("//127.0.0.1", "http"),
            ("http://usuario:clave@127.0.0.1/", "usuario"),
            ("http://usuario@127.0.0.1/", "usuario"),
            ("http://127.0.0.1/#frag", "fragmento"),
            ("http://127.0.0.1:99999/", "válida"),
        ],
    )
    def test_malformed_or_dangerous_urls_are_rejected(self, url, message):
        with pytest.raises(TargetError, match=message):
            validate_web_target(url, owns_target=True)

    def test_unresolvable_hosts_are_rejected(self, monkeypatch):
        resolving(monkeypatch, {})
        with pytest.raises(TargetError, match="resolver"):
            validate_web_target("http://no-existe.example/", owns_target=True)


class TestImageName:
    @pytest.mark.parametrize(
        "name",
        ["alpine", "alpine:3.10", "mi-app:1.0", "ghcr.io/org/app:v1", "registry:5000/team/app:tag", "app@sha256:" + "a" * 64],
    )
    def test_valid_names(self, name):
        assert validate_image_name(name) == name

    @pytest.mark.parametrize("name", ["", "-x", "--privileged", "a b", "a;b", "$(id)", "a`b`", "a\nb", ".oculta", "/abs", "x" * 300])
    def test_names_that_could_be_read_as_options_or_commands_are_rejected(self, name):
        with pytest.raises(TargetError):
            validate_image_name(name)


class TestZapParser:
    def result(self):
        return parse_zap(load("zap.json"))

    def test_one_finding_per_alert_with_the_site_as_location(self):
        out = self.result()

        assert len(out.findings) == 10 and out.scanned == ["http://127.0.0.1:8777"]
        assert {f.file for f in out.findings} == {"http://127.0.0.1:8777"}
        assert all(f.tool == "zap" and f.category is Category.WEB for f in out.findings)

    def test_severity_follows_the_risk_and_drops_a_level_when_confidence_is_low(self):
        by_rule = {f.rule_id: f for f in self.result().findings}

        assert by_rule["10038-1"].severity is Severity.MEDIUM  # Medium (High confidence)
        assert by_rule["10021"].severity is Severity.LOW
        assert by_rule["10049-3"].severity is Severity.INFO  # Informational
        assert by_rule["10202"].severity is Severity.LOW  # Medium (Low confidence) baja un escalón

    def test_description_has_cwe_urls_and_solution_as_plain_text(self):
        finding = {f.rule_id: f for f in self.result().findings}["10038-1"]

        assert "CWE-693" in finding.description and "5 URL afectada(s)" in finding.description
        assert "Solución:" in finding.description
        assert "<p>" not in finding.description and "</p>" not in finding.description

    def test_urls_beyond_the_limit_are_counted_not_listed(self):
        data = load("zap.json")
        alert = data["site"][0]["alerts"][1]
        alert["instances"] = [{"uri": f"http://127.0.0.1:8777/p{i}", "method": "GET"} for i in range(9)]

        text = {f.rule_id: f for f in parse_zap(data).findings}[alert["alertRef"]].description
        assert "9 URL afectada(s)" in text and "y 4 más" in text and "/p8" not in text

    def test_the_fingerprint_does_not_depend_on_which_pages_the_crawl_found(self):
        a, b = load("zap.json"), load("zap.json")
        b["site"][0]["alerts"][0]["instances"].reverse()
        b["site"][0]["alerts"][1]["instances"] = b["site"][0]["alerts"][1]["instances"][:2]  # otro rastreo, menos páginas

        assert [f.fingerprint for f in parse_zap(a).findings] == [f.fingerprint for f in parse_zap(b).findings]

    def test_an_empty_site_is_still_reported_as_scanned(self):
        out = parse_zap({"site": [{"@name": "http://x", "alerts": []}]})
        assert out.findings == [] and out.scanned == ["http://x"]

    def test_urls_found_by_the_crawler_are_untrusted_and_trigger_the_hostile_alert(self):
        data = load("zap.json")
        data["site"][0]["alerts"][0]["instances"] = [{"uri": "http://127.0.0.1:8777/<img src=x onerror=alert(1)>", "method": "GET"}]
        out = parse_zap(data)

        alerts, hits = find_hostile_content(out.findings, {}, [], {"zap": out.scanned})
        assert alerts and any("onerror" in h.fragment for h in hits)
        html = to_html(ScanResult(target="http://127.0.0.1:8777", findings=out.findings, alerts=alerts, hostile_hits=hits))
        assert "<img src=x" not in html and "&lt;img src=x onerror=alert(1)&gt;" in html


class TestTrivyImageParser:
    def output(self):
        return parse_trivy_image(load("trivy-image.json"), "mi-app:1.0")

    def test_system_packages_language_packages_and_secrets_get_their_own_category(self):
        cats = {}
        for f in self.output().findings:
            cats[f.category] = cats.get(f.category, 0) + 1

        assert cats == {Category.IMAGE: 6, Category.DEPENDENCY: 7, Category.SECRET: 1}

    def test_the_internal_mount_point_never_leaks_into_names(self):
        out = self.output()

        assert out.scanned == ["mi-app:1.0 (alpine 3.15.0)", "Python", "app/.env"]
        assert not any("/target" in f.file for f in out.findings)

    def test_language_packages_are_located_by_their_path(self):
        deps = [f for f in self.output().findings if f.category is Category.DEPENDENCY]
        assert all(f.file.startswith("usr/local/lib/python") for f in deps)

    def test_secrets_stay_masked_and_critical(self):
        [secret] = [f for f in self.output().findings if f.category is Category.SECRET]

        assert secret.file == "app/.env" and secret.severity is Severity.CRITICAL
        assert "****" in secret.snippet and "ghp_" not in secret.snippet


def capture_docker(monkeypatch, write=None):
    """Sustituye subprocess.run: guarda cada comando y, si se pide, escribe el informe donde lo haría el contenedor."""
    calls = []

    def fake(command, **kwargs):
        calls.append(command)
        if write and command[:2] == ["docker", "run"]:
            out_mount = next(command[i + 1] for i, arg in enumerate(command) if arg == "-v" and command[i + 1].split(":", 1)[1].startswith(write[0]))
            (Path(out_mount.split(":", 1)[0]) / write[1]).write_text(write[2])
        if command[:3] == ["docker", "image", "inspect"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[:2] == ["docker", "save"]:
            Path(command[3]).write_bytes(b"tar")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake)
    return calls


class TestScopeRegex:
    """Lo que el rastreo puede visitar. Una web hostil enlazará a cualquier URL que parezca del destino."""

    def match(self, url, candidate):
        return re.fullmatch(scope_regex(url), candidate) is not None

    @pytest.mark.parametrize(
        "url, candidate",
        [
            ("http://127.0.0.1:1234", "http://127.0.0.1:1234"),
            ("http://127.0.0.1:1234", "http://127.0.0.1:1234/"),
            ("http://127.0.0.1:1234", "http://127.0.0.1:1234/a/b.html?x=1&y=2#frag"),
            ("http://127.0.0.1:1234/", "http://127.0.0.1:1234/otra"),
            ("https://mia.example", "https://mia.example/x"),
            ("https://mia.example", "https://mia.example:443/x"),  # puerto por defecto, con o sin él
            ("http://mia.example", "http://mia.example:80/x"),
            ("https://mia.example", "HTTPS://MIA.EXAMPLE/x"),  # esquema y host no distinguen mayúsculas
            ("https://mia.example/app", "https://mia.example/app"),
            ("https://mia.example/app/", "https://mia.example/app/dentro?x=1"),
            ("https://mia.example/app", "https://mia.example/app?x=1"),
            ("http://[::1]:3000", "http://[::1]:3000/x"),
        ],
    )
    def test_urls_of_the_target_are_in_scope(self, url, candidate):
        assert self.match(url, candidate)

    @pytest.mark.parametrize(
        "url, candidate",
        [
            # el host sigue con más texto
            ("https://mia.example", "https://mia.example.evil.com/"),
            ("https://mia.example", "https://mia.examplex/"),
            ("http://127.0.0.1:1234", "http://127.0.0.1.evil.com:1234/"),
            # `mia.example` como usuario y otro host real
            ("https://mia.example", "https://mia.example@evil.com/"),
            ("https://mia.example", "https://mia.example:clave@evil.com/"),
            ("http://127.0.0.1:1234", "http://127.0.0.1:1234@evil.com/"),
            ("https://mia.example", "https://mia.example\\@evil.com/"),
            # el puerto es un prefijo del de otro servicio
            ("http://127.0.0.1:1234", "http://127.0.0.1:12345/enlazado"),
            ("http://127.0.0.1:1234", "http://127.0.0.1:123/"),
            ("http://127.0.0.1:1234", "http://127.0.0.1/"),  # sin puerto = el 80, no el 1234
            ("https://mia.example", "https://mia.example:8443/"),
            ("http://mia.example", "http://mia.example:8080/"),
            # otro esquema
            ("https://mia.example", "http://mia.example/"),
            ("http://mia.example", "https://mia.example/"),
            ("https://mia.example", "ftp://mia.example/"),
            # la ruta es un prefijo de otra
            ("https://mia.example/app", "https://mia.example/application"),
            ("https://mia.example/app", "https://mia.example/app.evil"),
            ("https://mia.example/app", "https://mia.example/"),
            ("https://mia.example/app", "https://mia.example/otra"),
            # otros hosts
            ("http://127.0.0.1:1234", "http://127.0.0.2:1234/"),
            ("http://127.0.0.1:1234", "http://localhost:1234/"),
            ("https://mia.example", "https://otro.example/"),
            ("https://mia.example", "https://mia.example./"),
            ("http://[::1]:3000", "http://[::2]:3000/"),
        ],
    )
    def test_look_alike_urls_are_out_of_scope(self, url, candidate):
        assert not self.match(url, candidate)

    def test_the_context_url_always_ends_in_a_slash(self):
        assert context_url("http://127.0.0.1:1234") == "http://127.0.0.1:1234/"
        assert context_url("http://127.0.0.1:1234/") == "http://127.0.0.1:1234/"
        assert context_url("https://mia.example/app") == "https://mia.example/app/"
        assert context_url("http://[::1]:3000/x/?q=1") == "http://[::1]:3000/x/"

    @pytest.mark.parametrize(
        "url, candidate",
        [
            ("http://127.0.0.1:1234", "http://127.0.0.1:12345/enlazado"),
            ("http://127.0.0.1:1234", "http://127.0.0.1:1234.evil.com/"),
            ("http://127.0.0.1:1234", "http://127.0.0.1:1234@evil.com/"),
            ("https://mia.example", "https://mia.example.evil.com/"),
            ("https://mia.example", "https://mia.example@evil.com/"),
            ("https://mia.example/app", "https://mia.example/application"),
            ("https://mia.example/app", "https://mia.example/app.evil"),
        ],
    )
    def test_the_automation_framework_adds_the_context_url_as_a_prefix_and_that_prefix_is_safe(self, url, candidate):
        # El AF trata cada URL del contexto como `url.*`. Sin la barra final, esa suma reintroducía los
        # destinos parecidos que scope_regex excluye (comprobado con ZAP real).
        assert not re.fullmatch(re.escape(context_url(url)) + ".*", candidate)
        assert re.fullmatch(re.escape(context_url(url)) + ".*", context_url(url) + "dentro")

    def test_regex_metacharacters_in_the_host_or_path_are_escaped(self):
        assert self.match("http://a.b:80/x+y", "http://a.b/x+y/z")
        assert not self.match("http://a.b", "http://aXb/")  # el punto no es un comodín
        assert not self.match("https://mia.example/a.b", "https://mia.example/aXb")

    def test_it_only_uses_constructs_that_python_and_java_read_the_same_way(self):
        # ZAP la evalúa con java.util.regex: solo grupos (?:..) y (?i:..), sin referencias ni anclas especiales.
        assert not re.search(r"\\[1-9]|\(\?<|\(\?P|\\p\{|\*\+|\+\+", scope_regex("https://mia.example/app"))


class TestZapRunner:
    """ZAP no se lanza con zap-baseline.py (abre la API y un proxy sin clave en todas las interfaces)."""

    def run(self, monkeypatch, target, minutes=2):
        seen = {"plan": None, "commands": []}

        def fake(command, **kwargs):
            seen["commands"].append(command)
            if command[:2] == ["docker", "run"]:
                out_dir = Path(next(c.split(":", 1)[0] for c in command if c.endswith(":/zap/wrk")))
                seen["plan"] = (out_dir / "plan.yaml").read_text(encoding="utf-8")  # lo que verá el contenedor
                (out_dir / "zap.json").write_text(json.dumps(load("zap.json")))
            return subprocess.CompletedProcess(command, 0, "", "")

        monkeypatch.setattr(subprocess, "run", fake)
        out = ZapRunner(target, minutes=minutes).run()
        return seen["commands"][0], seen["plan"], out

    LOCAL = WebTarget("http://127.0.0.1:8000", "127.0.0.1", True)

    def test_loopback_uses_the_host_network_and_pins_nothing(self, monkeypatch):
        command, _, out = self.run(monkeypatch, self.LOCAL)

        assert command[command.index("--network") + 1] == "host" and "--add-host" not in command
        assert len(out.findings) == 10

    def test_an_external_target_pins_every_validated_ip_and_never_gets_the_host_network(self, monkeypatch):
        target = WebTarget("https://mia.example", "mia.example", False, ("93.184.216.34", "2606:2800::1"))
        command, _, _ = self.run(monkeypatch, target)

        assert "--network" not in command
        pins = [command[i + 1] for i, arg in enumerate(command) if arg == "--add-host"]
        assert pins == ["mia.example:93.184.216.34", "mia.example:2606:2800::1"]

    def test_localhost_is_pinned_too_so_a_changing_dns_cannot_redirect_the_scan(self, monkeypatch):
        command, _, _ = self.run(monkeypatch, WebTarget("http://localhost:3000", "localhost", True, ("127.0.0.1", "::1")))

        pins = [command[i + 1] for i, arg in enumerate(command) if arg == "--add-host"]
        assert pins == ["localhost:127.0.0.1", "localhost:::1"]

    def test_nothing_from_the_host_is_mounted_but_the_report_directory_and_it_never_runs_as_root(self, monkeypatch):
        command, _, _ = self.run(monkeypatch, self.LOCAL)
        mounts = [command[i + 1] for i, arg in enumerate(command) if arg == "-v"]

        assert len(mounts) == 1 and mounts[0].endswith(":/zap/wrk")
        assert command[command.index("--user") + 1] != "0:0" and "docker.sock" not in " ".join(command)

    def test_it_never_uses_the_baseline_script_nor_exposes_a_daemon(self, monkeypatch):
        command, _, _ = self.run(monkeypatch, self.LOCAL)
        text = " ".join(command)

        assert "zap-baseline.py" not in text and "zap-full-scan.py" not in text
        assert "-daemon" not in text and "0.0.0.0" not in text and "api.disablekey" not in text
        assert "-host" not in command  # sin -host, ZAP no escucha en todas las interfaces

    def test_the_callback_server_of_the_oast_addon_is_limited_to_loopback_in_both_phases(self, monkeypatch):
        command, _, _ = self.run(monkeypatch, self.LOCAL)
        script = command[-1]

        assert command[command.index("--entrypoint") + 1] == "sh" and command[-2] == "-c"
        assert script.count("-config oast.callback.localaddr=127.0.0.1") == 2  # instalación de reglas y escaneo
        assert "pscanrulesBeta" in script and "-autorun /zap/wrk/plan.yaml" in script

    def test_the_command_string_never_contains_user_data(self, monkeypatch):
        hostile = WebTarget("http://127.0.0.1:8000/;touch${IFS}/tmp/x", "127.0.0.1", True)
        command, plan, _ = self.run(monkeypatch, hostile)

        assert "touch" not in command[-1]  # la URL solo viaja dentro del plan, como dato
        assert "touch" in plan

    def test_the_plan_is_passive_and_limited_to_the_target(self, monkeypatch):
        import yaml

        _, text, _ = self.run(monkeypatch, WebTarget("http://127.0.0.1:8000/app", "127.0.0.1", True), minutes=3)
        plan = yaml.safe_load(text)

        assert [job["type"] for job in plan["jobs"]] == ["passiveScan-config", "spider", "passiveScan-wait", "report"]
        assert "activeScan" not in text and "attack" not in text.lower()
        assert plan["jobs"][1]["parameters"] == {"context": "secscan", "maxDuration": 3, "url": "http://127.0.0.1:8000/app"}
        context = plan["env"]["contexts"][0]
        assert context["name"] == "secscan" and context["includePaths"] == [scope_regex("http://127.0.0.1:8000/app")]
        assert context["urls"] == ["http://127.0.0.1:8000/app/"]  # con barra: el AF la usa como prefijo

    def test_a_url_with_yaml_syntax_stays_data(self, monkeypatch):
        import yaml

        url = "http://127.0.0.1:8000/x: {a: [b]} #c"
        _, text, _ = self.run(monkeypatch, WebTarget(url, "127.0.0.1", True))

        assert yaml.safe_load(text)["jobs"][1]["parameters"]["url"] == url

    def test_a_missing_report_is_an_error_not_a_clean_result(self, monkeypatch):
        monkeypatch.setattr(subprocess, "run", lambda command, **kwargs: subprocess.CompletedProcess(command, 0, "", ""))
        with pytest.raises(RunnerError, match="zap.json"):
            ZapRunner(self.LOCAL).run()


class TestFailureDetail:
    def test_the_error_shows_the_last_meaningful_lines_not_just_the_last_one(self, monkeypatch):
        log = "INFO: arranque\n\nAutomation plan failures:\n\tMissing URLs for context: {name=secscan}\n\nINFO: Created user preferences directory.\n"
        monkeypatch.setattr(subprocess, "run", lambda command, **kwargs: subprocess.CompletedProcess(command, 1, "", log))

        with pytest.raises(RunnerError) as error:
            ZapRunner(WebTarget("http://127.0.0.1:8000", "127.0.0.1", True)).run()

        assert "Missing URLs for context" in str(error.value) and "código 1" in str(error.value)

    def test_a_long_log_is_truncated(self, monkeypatch):
        monkeypatch.setattr(subprocess, "run", lambda command, **kwargs: subprocess.CompletedProcess(command, 2, "", "x" * 2000))
        with pytest.raises(RunnerError) as error:
            ZapRunner(WebTarget("http://127.0.0.1:8000", "127.0.0.1", True)).run()
        assert len(str(error.value)) < 400


class TestContainerLifecycle:
    """Si el escaneo vence o se interrumpe, el contenedor (con su red) no puede quedarse corriendo."""

    LOCAL = WebTarget("http://127.0.0.1:8000", "127.0.0.1", True)

    def interrupted_run(self, monkeypatch, exception):
        calls = []

        def fake(command, **kwargs):
            calls.append(command)
            if command[:2] == ["docker", "run"]:
                raise exception
            return subprocess.CompletedProcess(command, 0, "", "")

        monkeypatch.setattr(subprocess, "run", fake)
        return calls

    def test_a_timeout_kills_the_container_by_name(self, monkeypatch):
        calls = self.interrupted_run(monkeypatch, subprocess.TimeoutExpired("docker", 1))

        with pytest.raises(RunnerError, match="superó"):
            ZapRunner(self.LOCAL).run()

        run, kill = calls
        name = run[run.index("--name") + 1]
        assert kill == ["docker", "kill", name] and name.startswith("secscan-zap-")

    def test_ctrl_c_also_kills_the_container_and_still_propagates(self, monkeypatch):
        calls = self.interrupted_run(monkeypatch, KeyboardInterrupt())

        with pytest.raises(KeyboardInterrupt):
            ZapRunner(self.LOCAL).run()

        assert calls[1][:2] == ["docker", "kill"]

    def test_every_run_gets_a_different_name(self, monkeypatch):
        names = []

        def fake(command, **kwargs):
            if command[:2] == ["docker", "run"]:
                names.append(command[command.index("--name") + 1])
                out_dir = Path(next(c.split(":", 1)[0] for c in command if c.endswith(":/zap/wrk")))
                (out_dir / "zap.json").write_text(json.dumps(load("zap.json")))
            return subprocess.CompletedProcess(command, 0, "", "")

        monkeypatch.setattr(subprocess, "run", fake)
        ZapRunner(self.LOCAL).run()
        ZapRunner(self.LOCAL).run()

        assert len(set(names)) == 2

    def test_a_failing_kill_does_not_hide_the_timeout_error(self, monkeypatch):
        def fake(command, **kwargs):
            if command[:2] == ["docker", "kill"]:
                raise OSError("docker se fue")
            raise subprocess.TimeoutExpired("docker", 1)

        monkeypatch.setattr(subprocess, "run", fake)
        with pytest.raises(RunnerError, match="superó"):
            ZapRunner(self.LOCAL).run()


class TestImageRunner:
    def test_the_image_is_exported_to_a_tar_and_the_docker_socket_is_never_mounted(self, monkeypatch):
        calls = capture_docker(monkeypatch, write=("/out", "trivy.json", json.dumps(load("trivy-image.json"))))
        out = TrivyImageRunner("mi-app:1.0").run()

        inspect_call, save_call, run_call = calls
        assert inspect_call == ["docker", "image", "inspect", "mi-app:1.0"]
        assert save_call[:3] == ["docker", "save", "-o"] and save_call[-1] == "mi-app:1.0"
        assert "docker.sock" not in " ".join(run_call)
        tar_mount = next(run_call[i + 1] for i, arg in enumerate(run_call) if arg == "-v" and run_call[i + 1].endswith(":/target:ro"))
        assert tar_mount.startswith(save_call[3]) and run_call[run_call.index("--input") + 1] == "/target"
        assert len(out.findings) == 14 and out.scanned[0] == "mi-app:1.0 (alpine 3.15.0)"

    def test_the_tar_is_deleted_afterwards(self, monkeypatch):
        calls = capture_docker(monkeypatch, write=("/out", "trivy.json", json.dumps(load("trivy-image.json"))))
        TrivyImageRunner("mi-app:1.0").run()

        assert not Path(calls[1][3]).exists() and not Path(calls[1][3]).parent.exists()

    def test_an_image_that_is_not_local_gives_a_clear_error_and_nothing_else_runs(self, monkeypatch):
        calls = []

        def fake(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 1, "", "no such image")

        monkeypatch.setattr(subprocess, "run", fake)
        with pytest.raises(RunnerError, match="docker pull"):
            TrivyImageRunner("nada:1").run()
        assert len(calls) == 1  # solo el inspect: no se exportó ni se lanzó Trivy


class TestCli:
    runner = CliRunner()

    def test_web_to_a_non_local_host_needs_the_flag(self, monkeypatch):
        resolving(monkeypatch, {"ajeno.example": ["93.184.216.34"]})
        monkeypatch.setattr(cli, "scan_web", lambda *a, **k: pytest.fail("no debe escanear"))

        out = self.runner.invoke(cli.app, ["web", "https://ajeno.example"])
        assert out.exit_code == 2 and "--i-own-this" in out.output

    def test_web_to_localhost_runs_without_the_flag(self, monkeypatch):
        seen = {}

        def fake(target, config, minutes):
            seen.update(host=target.host, minutes=minutes)
            return ScanResult(target=target.url)

        monkeypatch.setattr(cli, "scan_web", fake)
        out = self.runner.invoke(cli.app, ["web", "http://127.0.0.1:8000", "--minutes", "3", "--fail-on", "none"])

        assert out.exit_code == 0 and seen == {"host": "127.0.0.1", "minutes": 3}

    def test_the_crawl_time_is_bounded(self):
        out = self.runner.invoke(cli.app, ["web", "http://127.0.0.1:8000", "--minutes", "999"])
        assert out.exit_code != 0

    def test_image_rejects_names_that_look_like_options(self, monkeypatch):
        monkeypatch.setattr(cli, "scan_image", lambda *a, **k: pytest.fail("no debe escanear"))

        out = self.runner.invoke(cli.app, ["image", "--", "--privileged"])
        assert out.exit_code == 2

    def test_image_scan_uses_the_shared_output_and_exit_codes(self, monkeypatch, tmp_path):
        from secscan.models import Finding

        bad = Finding(tool="trivy", rule_id="CVE-1", title="t", severity=Severity.CRITICAL, category=Category.IMAGE, file="x")
        monkeypatch.setattr(cli, "scan_image", lambda image, config: ScanResult(target=image, findings=[bad]))

        assert self.runner.invoke(cli.app, ["image", "app:1"]).exit_code == 1  # --fail-on high por defecto
        out = tmp_path / "r.md"
        assert self.runner.invoke(cli.app, ["image", "app:1", "--fail-on", "none", "--format", "md", "-o", str(out)]).exit_code == 0
        assert "# Informe de seguridad · app:1" in out.read_text(encoding="utf-8")

    def test_a_config_file_is_applied_to_web_and_image_scans(self, monkeypatch, tmp_path):
        cfg = tmp_path / "triage.yml"
        cfg.write_text("ignore:\n  rules: [CVE-1]\n")
        seen = {}
        monkeypatch.setattr(cli, "scan_image", lambda image, config: seen.setdefault("config", config) and ScanResult(target=image))

        self.runner.invoke(cli.app, ["image", "app:1", "--config", str(cfg), "--fail-on", "none"])
        assert isinstance(seen["config"], Config) and seen["config"].ignore.rules == ["CVE-1"]
