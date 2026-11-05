"""Los normalizadores se prueban con salidas reales guardadas: sin Docker, rápidos y deterministas."""

import json
from pathlib import Path

from secscan.models import Category, Severity
from secscan.runners.base import relative_path
from secscan.runners.gitleaks import parse_gitleaks
from secscan.runners.semgrep import parse_semgrep
from secscan.runners.trivy import parse_trivy

FIXTURES = Path(__file__).parent / "fixtures"


def load(name):
    return json.loads((FIXTURES / name).read_text())


def test_relative_path_strips_the_container_mount():
    assert relative_path("/target/src/x.py") == "src/x.py"
    assert relative_path("/otro/src/x.py", "/otro") == "src/x.py"
    assert relative_path("Dockerfile") == "Dockerfile"


class TestGitleaks:
    """Fixture: un proyecto de ejemplo inventado, con dos claves falsas en tests/."""

    def test_converts_secrets_with_relative_paths(self):
        findings = parse_gitleaks(load("gitleaks.json"))

        assert len(findings) == 2
        first = findings[0]
        assert first.file == "tests/test_client.py"
        assert (first.category, first.severity) == (Category.SECRET, Severity.HIGH)
        assert first.rule_id == "generic-api-key" and first.line_start == 1

    def test_never_keeps_the_real_secret(self):
        findings = parse_gitleaks(load("gitleaks.json"))

        assert all("REDACTED" in f.snippet for f in findings)


class TestSemgrep:
    """Fixture: un proyecto de ejemplo inventado (`app/server.py`) y un fichero con `# nosemgrep`."""

    def findings(self):
        return {f.rule_id: f for f in parse_semgrep(load("semgrep.sarif"))}

    def test_skips_results_suppressed_with_nosemgrep(self):
        # El SARIF trae el resultado de app/ignored.py con "suppressions": ya está triado.
        assert "app/ignored.py" not in {f.file for f in parse_semgrep(load("semgrep.sarif"))}

    def test_converts_all_the_other_results(self):
        assert set(self.findings()) == {
            "subprocess-shell-true", "avoid-pickle", "eval-detected", "dynamic-urllib-use-detected",
        }  # fmt: skip

    def test_paths_are_relative_and_short_rule_ids_are_used(self):
        finding = self.findings()["subprocess-shell-true"]

        assert finding.file == "app/server.py"
        assert finding.line_start == 7 and finding.category is Category.CODE

    def test_level_error_is_high_and_low_confidence_warnings_drop_to_low(self):
        findings = self.findings()

        assert findings["subprocess-shell-true"].severity is Severity.HIGH  # error, confianza media
        assert findings["avoid-pickle"].severity is Severity.LOW  # warning, confianza baja

    def test_a_warning_with_normal_confidence_stays_medium(self):
        sarif = {"runs": [{"tool": {"driver": {"rules": [{"id": "r", "properties": {"tags": ["HIGH CONFIDENCE"]}}]}}, "results": [
            {"ruleId": "r", "level": "warning", "message": {"text": "Algo."}, "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": "/target/a.py"}, "region": {"startLine": 1}}}]},
        ]}]}  # fmt: skip

        assert parse_semgrep(sarif)[0].severity is Severity.MEDIUM

    def test_cwe_goes_into_the_description(self):
        assert "CWE-78" in self.findings()["subprocess-shell-true"].description
        assert "CWE-502" in self.findings()["avoid-pickle"].description


class TestTrivy:
    """Fixture real: un proyecto de ejemplo inventado con requests==2.19.0, un fichero limpio y un Dockerfile sin endurecer."""

    def output(self):
        return parse_trivy(load("trivy.json"), root="/target")

    def test_vulnerabilities_become_dependency_findings(self):
        vulns = {f.rule_id: f for f in self.output().findings if f.category is Category.DEPENDENCY}

        assert len(vulns) == 5 and all(f.file == "requirements.txt" for f in vulns.values())
        assert vulns["CVE-2018-18074"].severity is Severity.HIGH
        assert "requests@2.19.0" in vulns["CVE-2018-18074"].description
        assert "Corregido en 2.20.0" in vulns["CVE-2018-18074"].description

    def test_a_vulnerability_without_a_fix_says_so(self):
        data = {"Results": [{"Target": "x.lock", "Vulnerabilities": [{
            "VulnerabilityID": "CVE-0", "PkgName": "p", "InstalledVersion": "1", "Severity": "CRITICAL"}]}]}

        finding = parse_trivy(data).findings[0]
        assert finding.severity is Severity.CRITICAL and "Sin versión corregida" in finding.description

    def test_only_failed_misconfigurations_are_reported(self):
        configs = [f for f in self.output().findings if f.category is Category.CONFIG]

        assert {f.rule_id for f in configs} == {"DS-0002", "DS-0026"}
        assert all(f.file == "Dockerfile" for f in configs)
        assert {f.rule_id: f.severity for f in configs}["DS-0002"] is Severity.HIGH  # corre como root

    def test_clean_targets_still_count_as_scanned(self):
        # "0 CVEs en clean/requirements.txt" es información: se miró y estaba limpio.
        scanned = self.output().scanned
        assert scanned == ["clean/requirements.txt", "requirements.txt", "Dockerfile"]
        assert not [f for f in self.output().findings if f.file == "clean/requirements.txt"]


class TestReadReport:
    def test_reads_a_regular_file(self, tmp_path):
        from secscan.runners.base import read_report

        (tmp_path / "r.json").write_text("[]")
        assert read_report(tmp_path, "r.json") == "[]"

    def test_rejects_missing_files_and_symlinks(self, tmp_path):
        import pytest

        from secscan.runners.base import RunnerError, read_report

        with pytest.raises(RunnerError):
            read_report(tmp_path, "no-existe.json")
        secret = tmp_path / "otro.txt"
        secret.write_text("x")
        (tmp_path / "r.json").symlink_to(secret)  # un enlace podría apuntar a cualquier fichero
        with pytest.raises(RunnerError):
            read_report(tmp_path, "r.json")


class TestSemgrepTitle:
    def test_title_is_the_first_sentence_of_the_message_not_the_rule_id(self):
        findings = {f.rule_id: f for f in parse_semgrep(load("semgrep.sarif"))}

        title = findings["eval-detected"].title
        assert title == "Detected the use of eval()"  # sin el punto final
        assert title != "eval-detected"

    def test_falls_back_to_the_rule_name_and_truncates_long_titles(self):
        from secscan.runners.semgrep import _title

        assert _title("", "mi-regla") == "mi-regla"
        assert len(_title("a" * 500, "x")) <= 120
