"""Informes HTML y Markdown: contenido, escape de entrada no confiable y salida del CLI."""

import re

import pytest
from typer.testing import CliRunner

from secscan import cli
from secscan.models import Category, Finding, ScanResult, Severity
from secscan.report_html import CSP, to_html
from secscan.report_md import escape, to_markdown

HOSTILE = '<script>alert(1)</script> [clic](http://malo.example) | `x` <img src=x onerror=alert(2)>\nlinea 2'


def finding(**overrides):
    values = dict(
        tool="semgrep", rule_id="rule-a", title="Regla A", severity=Severity.HIGH, category=Category.CODE,
        file="apps/x.py", line_start=10, snippet="urlopen(x)", description="Descripción",
    )  # fmt: skip
    return Finding(**{**values, **overrides})


def result(**overrides):
    values = dict(
        target="/home/alguien/secreto/mi-repo", scanned_at="2026-11-05T10:00:00+00:00",
        findings=[finding(), finding(rule_id="b", severity=Severity.LOW, title="Baja")],
        scanned={"semgrep": ["."], "trivy": ["uv.lock", "Dockerfile"]},
    )  # fmt: skip
    return ScanResult(**{**values, **overrides})


class TestHtml:
    def test_is_a_self_contained_document(self):
        html = to_html(result())

        assert html.startswith("<!doctype html>") and "<title>secscan · mi-repo</title>" in html
        assert "<script" not in html  # sin JavaScript
        assert not re.search(r"(src|href)=", html)  # sin recursos externos
        assert not re.search(r"url\(", html)
        assert CSP in html and "default-src 'none'" in html

    def test_shows_counts_groups_and_the_fingerprint(self):
        html = to_html(result())

        assert "Hallazgos" in html and "Alta (1)" in html and "Baja (1)" in html
        assert finding().fingerprint in html and "apps/x.py:10" in html

    def test_does_not_reveal_the_full_local_path(self):
        html = to_html(result())

        assert "mi-repo" in html and "/home/alguien" not in html

    def test_untrusted_text_cannot_inject_markup(self):
        hostile = result(
            findings=[finding(title=HOSTILE, rule_id=HOSTILE, file=HOSTILE, description=HOSTILE, snippet=HOSTILE)],
            errors={"x": HOSTILE}, warnings=[HOSTILE], scanned={HOSTILE: [HOSTILE]},
        )  # fmt: skip
        html = to_html(hostile)

        assert "<script>alert" not in html and "<img src=x" not in html
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html

    def test_incomplete_scan_is_never_shown_as_clean(self):
        html = to_html(result(findings=[], errors={"trivy": "boom"}))

        assert "Escaneo incompleto" in html and "Sin hallazgos" not in html and "boom" in html

    def test_a_clean_scan_says_so(self):
        html = to_html(result(findings=[]))
        assert "Sin hallazgos" in html and "Escaneo incompleto" not in html

    def test_empty_result_does_not_break(self):
        assert "<html" in to_html(ScanResult(target="x"))


class TestMarkdown:
    def test_has_summary_findings_coverage_and_fingerprints(self):
        md = to_markdown(result())

        assert md.startswith("# Informe de seguridad · mi-repo")
        assert "| Alta | 1 |" in md and "| Baja | 1 |" in md and "**Total: 2**" in md
        assert "### Alta (1)" in md and f"`{finding().fingerprint}`" in md
        assert "✓ semgrep: analizado (.)" in md and "/home/alguien" not in md

    def test_order_is_from_most_to_least_severe(self):
        md = to_markdown(result(findings=[finding(severity=Severity.LOW, rule_id="l"), finding(severity=Severity.CRITICAL, rule_id="c")]))
        assert md.index("### Crítica") < md.index("### Baja")

    def test_untrusted_text_cannot_inject_links_html_or_break_tables(self):
        md = to_markdown(result(findings=[finding(title=HOSTILE, file=HOSTILE)], errors={"x": HOSTILE}, warnings=[HOSTILE]))

        assert "<script>" not in md and "<img" not in md
        assert "[clic](" not in md  # el enlace queda escapado: \[clic\]\(...
        assert "\n" not in escape(HOSTILE)
        row = next(line for line in md.splitlines() if line.startswith("| semgrep"))
        assert len(re.findall(r"(?<!\\)\|", row)) == 6  # 5 columnas: las barras del texto están escapadas

    def test_incomplete_scan_is_flagged(self):
        md = to_markdown(result(findings=[], errors={"trivy": "boom"}))
        assert "Escaneo incompleto" in md and "Sin hallazgos" not in md

    def test_long_text_is_truncated(self):
        assert len(escape("a" * 5000)) < 400

    def test_empty_result_does_not_break(self):
        assert "Sin hallazgos" in to_markdown(ScanResult(target="x"))


class TestCli:
    runner = CliRunner()

    def invoke(self, monkeypatch, tmp_path, *args):
        monkeypatch.setattr(cli, "scan", lambda *a, **k: result())
        return self.runner.invoke(cli.app, ["scan", str(tmp_path), "--fail-on", "none", *args])

    def test_html_and_md_formats_go_to_a_file(self, monkeypatch, tmp_path):
        for fmt, marker in (("html", "<!doctype html>"), ("md", "# Informe de seguridad")):
            out = tmp_path / f"r.{fmt}"
            assert self.invoke(monkeypatch, tmp_path, "--format", fmt, "-o", str(out)).exit_code == 0
            assert out.read_text(encoding="utf-8").startswith(marker)

    def test_report_dir_writes_every_report_at_once(self, monkeypatch, tmp_path):
        target = tmp_path / "informe" / "nuevo"  # la carpeta se crea si no existe
        out = self.invoke(monkeypatch, tmp_path, "--report-dir", str(target))

        assert out.exit_code == 0
        assert sorted(p.name for p in target.iterdir()) == [
            ".gitignore", "secscan-report.html", "secscan-report.json", "secscan-report.md", "secscan-report.sarif",
        ]

    def test_markdown_to_stdout(self, monkeypatch, tmp_path):
        out = self.invoke(monkeypatch, tmp_path, "--format", "md")
        assert out.exit_code == 0 and "# Informe de seguridad" in out.stdout

    def test_table_to_a_file_has_no_colors(self, monkeypatch, tmp_path):
        out_file = tmp_path / "tabla.txt"
        assert self.invoke(monkeypatch, tmp_path, "-o", str(out_file)).exit_code == 0
        assert "\x1b[" not in out_file.read_text(encoding="utf-8")


class TestGithubNotificationsAreNeutralized:
    """En un comentario de GitHub, `@usuario` notifica a esa persona y `#123` enlaza esa incidencia."""

    HOSTILE = "@torvalds y @org/equipo, ver #123 y org/repo#4"

    def test_mentions_and_issue_references_are_broken_with_a_zero_width_space(self):
        out = escape(self.HOSTILE)

        assert not re.search(r"@(?!​)\w", out) and not re.search(r"#(?!​)\d", out)
        assert out.replace("​", "").replace("\\", "") == self.HOSTILE.replace("&", "&amp;")

    def test_it_applies_to_every_field_that_reaches_the_report(self):
        md = to_markdown(
            result(findings=[finding(title="@torvalds", file="@org/equipo/#1.py", rule_id="#99")], errors={"x": "@root"}, warnings=["@admin"])
        )

        assert not re.search(r"@(?!​)\w", md) and not re.search(r"(?<!\\)#(?!​)\d", md)


class TestGeneratedTimeIsShownInMadridTime:
    """«Generado» sale en hora de Madrid, con un paréntesis que avisa de que está convertida. El JSON sigue en UTC.

    El comentario que publica github-actions en el PR (y el resumen del job) es este mismo Markdown."""

    @staticmethod
    def label(iso):
        from secscan.report import generated_label

        return generated_label(iso)

    def test_winter_is_one_hour_ahead_of_utc(self):
        assert self.label("2026-11-05T12:29:08+00:00") == "5 de noviembre de 2026, 13:29 (hora de Madrid)"

    def test_summer_time_is_two_hours_ahead(self):
        assert self.label("2026-07-15T12:00:00+00:00") == "15 de julio de 2026, 14:00 (hora de Madrid)"

    def test_the_day_and_the_year_roll_over(self):
        assert self.label("2026-12-31T23:30:00+00:00") == "1 de enero de 2027, 00:30 (hora de Madrid)"

    def test_the_clock_change_days_are_handled_by_the_timezone_database(self):
        # El último domingo de octubre de 2026 (día 25) se vuelve al horario de invierno a la 01:00 UTC.
        assert self.label("2026-10-25T00:30:00+00:00") == "25 de octubre de 2026, 02:30 (hora de Madrid)"
        assert self.label("2026-10-25T01:30:00+00:00") == "25 de octubre de 2026, 02:30 (hora de Madrid)"
        # El último domingo de marzo (día 29) se pasa al de verano.
        assert self.label("2026-03-29T00:30:00+00:00") == "29 de marzo de 2026, 01:30 (hora de Madrid)"
        assert self.label("2026-03-29T01:30:00+00:00") == "29 de marzo de 2026, 03:30 (hora de Madrid)"

    def test_a_time_with_another_offset_is_converted_too(self):
        assert self.label("2026-11-05T13:29:08+01:00") == "5 de noviembre de 2026, 13:29 (hora de Madrid)"

    def test_without_a_zone_it_is_taken_as_utc(self):
        assert self.label("2026-11-05T12:29:08") == "5 de noviembre de 2026, 13:29 (hora de Madrid)"

    def test_something_that_is_not_a_date_gives_nothing(self):
        assert self.label("basura") is None and self.label("") is None

    def test_markdown_and_html_show_it(self):
        text = "Generado: 5 de noviembre de 2026, 11:00 (hora de Madrid)"
        both = result(scanned_at="2026-11-05T10:00:00+00:00")

        assert text in to_markdown(both) and text in to_html(both)
        assert "2026-11-05T10:00:00" not in to_markdown(both) + to_html(both)  # ya no sale el ISO

    def test_text_that_is_not_a_date_is_shown_escaped(self):
        hostile = result(scanned_at="<script>alert(1)</script> @alguien")

        assert "<script>" not in to_markdown(hostile) and "<script>" not in to_html(hostile)
        assert "&lt;script&gt;" in to_html(hostile)

    def test_the_json_keeps_the_machine_friendly_iso_utc(self):
        import json

        from secscan.report import to_json

        assert json.loads(to_json(result(scanned_at="2026-11-05T10:00:00+00:00")))["scanned_at"] == "2026-11-05T10:00:00+00:00"

    def test_the_scan_still_stores_utc(self, tmp_path):
        from datetime import datetime

        from secscan.config import Config
        from secscan.scanner import build_result

        stored = datetime.fromisoformat(build_result(tmp_path, {}, {}, Config()).scanned_at)
        assert stored.utcoffset().total_seconds() == 0
