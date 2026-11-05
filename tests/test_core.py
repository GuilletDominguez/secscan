"""Modelo, configuración, orquestador, informes y CLI."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secscan import cli
from secscan.config import Config, ConfigError, load_config
from secscan.models import Category, Finding, ScanResult, Severity
from secscan.report import to_json, to_sarif
from secscan.runners.base import RunnerOutput
from secscan.scanner import build_result


def finding(**overrides):
    values = dict(
        tool="semgrep", rule_id="rule-a", title="Regla A", severity=Severity.MEDIUM,
        category=Category.CODE, file="apps/x.py", line_start=10, snippet="urlopen(x)",
    )  # fmt: skip
    return Finding(**{**values, **overrides})


class TestFingerprint:
    def test_survives_a_line_change_and_whitespace(self):
        assert finding(line_start=10).fingerprint == finding(line_start=99, snippet="  urlopen(x) ").fingerprint

    def test_changes_with_rule_file_or_snippet(self):
        base = finding().fingerprint
        assert finding(rule_id="rule-b").fingerprint != base
        assert finding(file="apps/y.py").fingerprint != base
        assert finding(snippet="otra cosa").fingerprint != base

    def test_severity_parse_is_tolerant(self):
        assert Severity.parse("critical") is Severity.CRITICAL
        assert Severity.parse("raro") is Severity.INFO
        assert Severity.HIGH > Severity.MEDIUM


class TestConfig:
    def test_without_a_file_nothing_is_ignored(self, tmp_path):
        assert not load_config(tmp_path).is_ignored(finding())

    def test_ignores_by_path_rule_and_fingerprint(self, tmp_path):
        target = finding(file="src/pkg/tests/test_client.py", rule_id="generic-api-key")
        config = Config.model_validate({
            "ignore": {
                "paths": ["**/tests/**"],
                "rules": ["noisy-rule"],
                "findings": [{"id": finding().fingerprint, "reason": "URL fija"}],
            }
        })  # fmt: skip

        assert config.is_ignored(target)  # por ruta
        assert config.is_ignored(finding(rule_id="noisy-rule"))  # por regla
        assert config.is_ignored(finding())  # por huella
        assert not config.is_ignored(finding(file="apps/real.py", rule_id="otra"))

    def test_path_glob_also_matches_at_the_root(self):
        config = Config.model_validate({"ignore": {"paths": ["**/tests/**"]}})
        assert config.is_ignored(finding(file="tests/test_x.py"))

    def test_an_ignored_finding_needs_a_reason(self, tmp_path):
        (tmp_path / ".secscan.yml").write_text("ignore:\n  findings:\n    - id: abc\n")
        with pytest.raises(ConfigError):
            load_config(tmp_path)

    def test_empty_and_broken_files(self, tmp_path):
        (tmp_path / ".secscan.yml").write_text("")
        assert load_config(tmp_path) == Config()
        (tmp_path / ".secscan.yml").write_text("ignore: [")
        with pytest.raises(ConfigError):
            load_config(tmp_path)


class TestBuildResult:
    def test_dedupes_sorts_and_suppresses(self, tmp_path):
        low = finding(rule_id="low", severity=Severity.LOW, file="a.py")
        critical = finding(rule_id="crit", severity=Severity.CRITICAL, file="z.py")
        noisy = finding(rule_id="noisy", file="tests/t.py")
        outputs = {
            "semgrep": RunnerOutput(findings=[low, critical, critical, noisy], scanned=["."]),
            "trivy": RunnerOutput(scanned=["uv.lock"]),
        }
        config = Config.model_validate({"ignore": {"paths": ["tests/**"]}})

        result = build_result(tmp_path, outputs, {}, config)

        assert [f.rule_id for f in result.findings] == ["crit", "low"]  # sin el duplicado ni el ignorado
        assert result.suppressed == 1
        assert result.scanned == {"semgrep": ["."], "trivy": ["uv.lock"]}

    def test_a_failed_tool_is_recorded_not_hidden(self, tmp_path):
        result = build_result(tmp_path, {}, {"trivy": "Docker no está instalado"}, Config())
        assert result.errors == {"trivy": "Docker no está instalado"} and result.findings == []


class TestReports:
    def result(self):
        return ScanResult(target="/repo", findings=[finding(severity=Severity.HIGH)])

    def test_json_includes_the_fingerprint(self):
        data = json.loads(to_json(self.result()))
        assert data["findings"][0]["fingerprint"] == finding().fingerprint

    def test_sarif_has_levels_locations_and_fingerprints(self):
        sarif = json.loads(to_sarif(self.result()))
        result = sarif["runs"][0]["results"][0]

        assert sarif["version"] == "2.1.0" and result["level"] == "error"
        assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 10
        assert result["partialFingerprints"]["secscan/v1"] == finding().fingerprint


class TestCli:
    runner = CliRunner()

    def run(self, monkeypatch, tmp_path, result, *args):
        monkeypatch.setattr(cli, "scan", lambda *a, **k: result)
        return self.runner.invoke(cli.app, ["scan", str(tmp_path), *args])

    def test_fails_when_findings_reach_the_threshold(self, monkeypatch, tmp_path):
        result = ScanResult(target="x", findings=[finding(severity=Severity.HIGH)])
        assert self.run(monkeypatch, tmp_path, result).exit_code == 1  # --fail-on high por defecto
        assert self.run(monkeypatch, tmp_path, result, "--fail-on", "critical").exit_code == 0
        assert self.run(monkeypatch, tmp_path, result, "--fail-on", "none").exit_code == 0

    def test_a_tool_error_is_never_reported_as_clean(self, monkeypatch, tmp_path):
        result = ScanResult(target="x", errors={"trivy": "boom"})
        assert self.run(monkeypatch, tmp_path, result).exit_code == 2

    def test_json_goes_to_stdout_and_is_valid(self, monkeypatch, tmp_path):
        result = ScanResult(target="x", findings=[finding(severity=Severity.LOW)])
        out = self.run(monkeypatch, tmp_path, result, "--format", "json")

        assert out.exit_code == 0 and json.loads(out.stdout)["findings"][0]["rule_id"] == "rule-a"

    def test_unknown_tool_is_rejected(self, monkeypatch, tmp_path):
        assert self.run(monkeypatch, tmp_path, ScanResult(target="x"), "--tools", "nope").exit_code == 2


class TestMarkupInjection:
    """Títulos, rutas y errores vienen de repos ajenos: Rich no debe interpretarlos como marcado."""

    def test_untrusted_text_is_printed_literally(self):
        from io import StringIO

        from rich.console import Console

        from secscan.report import print_table

        hostile = "[bold red]FALSO[/] [link=https://evil.example]clic[/link]"
        result = ScanResult(
            target="x",
            findings=[finding(title=hostile, rule_id="[red]r", file="a/[b].py")],
            errors={"trivy": hostile},
        )
        buffer = StringIO()
        print_table(result, Console(file=buffer, width=200, force_terminal=False))

        assert hostile in buffer.getvalue().replace("\n", " ")
        assert "[red]r" in buffer.getvalue() and "a/[b].py" in buffer.getvalue()


class TestStrictConfig:
    """Una errata en `.secscan.yml` no debe parecer que funciona y no ignorar nada."""

    @pytest.mark.parametrize(
        "text",
        [
            "ignore:\n  rulez: [x]\n",  # errata en una clave
            "ignores:\n  rules: [x]\n",  # errata en la raíz
            "ignore:\n  findings:\n    - id: abc\n      reason: ok\n      motivo: otra cosa\n",  # clave de más
        ],
    )
    def test_unknown_keys_are_an_error(self, tmp_path, text):
        (tmp_path / ".secscan.yml").write_text(text)

        with pytest.raises(ConfigError, match="no es válido"):
            load_config(tmp_path)

    def test_a_correct_file_still_loads(self, tmp_path):
        (tmp_path / ".secscan.yml").write_text(
            "ignore:\n  paths: ['**/tests/**']\n  rules: [x]\n  findings:\n    - id: abc\n      reason: ok\n"
        )
        assert load_config(tmp_path).ignore.rules == ["x"]


class TestTargetKeepsNoLocalPath:
    def test_the_result_stores_only_the_folder_name_not_the_full_path(self, tmp_path):
        folder = tmp_path / "usuario" / "mi-proyecto"
        folder.mkdir(parents=True)

        result = build_result(folder, {}, {}, Config())

        assert result.target == "mi-proyecto"
        assert str(tmp_path) not in to_json(result)  # ni en el JSON que se comparte

    def test_the_root_folder_does_not_end_up_empty(self):
        assert build_result(Path("/"), {}, {}, Config()).target == "/"

    def test_the_display_name_in_the_reports_is_unchanged(self, tmp_path):
        from secscan.report import display_name

        folder = tmp_path / "mi-proyecto"
        folder.mkdir()
        assert display_name(build_result(folder, {}, {}, Config())) == "mi-proyecto"
