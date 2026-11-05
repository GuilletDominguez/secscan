"""Lo que hace falta para publicar el repositorio sin sorpresas."""

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def read(name):
    return (ROOT / name).read_text(encoding="utf-8")


def test_there_are_no_policy_files_that_ask_anyone_to_notify_anyone():
    # Es una herramienta de uso libre: no hay a quién avisar. Sin SECURITY.md, GitHub tampoco muestra «Security policy».
    for name in ("SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md"):
        assert not (ROOT / name).exists(), name


def test_the_license_is_the_unlicense_and_names_nobody():
    text = read("LICENSE")
    project = tomllib.loads(read("pyproject.toml"))["project"]

    assert text.startswith("This is free and unencumbered software released into the public domain.")
    assert "AS IS" in text and "Copyright" not in text  # sin titular: no hay nombre que poner
    assert project["license"] == "Unlicense" and project["license-files"] == ["LICENSE"]


def test_line_endings_are_normalized_and_fixtures_are_marked_as_generated():
    text = read(".gitattributes")
    assert "* text=auto eol=lf" in text and "tests/fixtures/** linguist-generated=true" in text


def test_the_readme_explains_requirements_license_and_where_it_was_tested():
    text = read("README.md")

    for fragment in ("## Requisitos e instalación", "**Docker**", "Probado solo en Linux", "## Licencia y uso libre", "(LICENSE)", "docs/configuration.md"):
        assert fragment in text, fragment


def test_the_package_metadata_makes_no_claim_it_cannot_back():
    project = tomllib.loads(read("pyproject.toml"))["project"]

    assert "Operating System :: POSIX :: Linux" in project["classifiers"]
    assert not any("Windows" in c or "MacOS" in c for c in project["classifiers"])  # no se ha probado
    assert "authors" not in project and "urls" not in project  # sin identidad ni enlaces personales
    assert not any(c.startswith("License ::") for c in project["classifiers"])  # con `license` SPDX no se usan


def test_nothing_is_published_that_a_fresh_clone_would_not_need():
    gitignore = read(".gitignore").splitlines()
    for pattern in (".venv/", "__pycache__/", ".pytest_cache/", "secscan-report.md", "informe/"):
        assert pattern in gitignore, pattern


class TestDocsMatchTheCode:
    """La documentación detallada se queda desfasada sin que nadie lo note: aquí se contrasta con el código real."""

    @staticmethod
    def doc(name):
        return read(f"docs/{name}.md")

    @staticmethod
    def section(text, start, end):
        """El trozo entre dos encabezados: `report-dir` es a la vez una entrada y una salida, cada una en su tabla."""
        return text.split(start, 1)[1].split(end, 1)[0]

    def test_the_docs_exist_and_the_readme_points_to_them(self):
        readme = read("README.md")
        for name in ("configuration", "limitations", "design"):
            assert (ROOT / "docs" / f"{name}.md").is_file() and f"docs/{name}.md" in readme, name

    def test_every_action_input_is_documented_with_its_real_default(self):
        import yaml

        inputs = yaml.safe_load(read("action.yml"))["inputs"]
        doc = self.section(self.doc("configuration"), "### Entradas", "### Salidas")
        for name, spec in inputs.items():
            rows = [line for line in doc.splitlines() if line.startswith(f"| `{name}` |")]
            assert len(rows) == 1, f"la entrada «{name}» no está documentada (o sale dos veces)"
            if spec["default"] != "":
                # La columna del valor por defecto, no cualquier parte de la fila: la descripción puede listar otros valores.
                cells = [cell.strip() for cell in rows[0].strip().strip("|").split("|")]
                assert cells[1] == f"`{spec['default']}`", f"{name}: el valor por defecto real es {spec['default']!r}, no {cells[1]}"

    def test_every_action_output_is_documented(self):
        import yaml

        doc = self.section(self.doc("configuration"), "### Salidas", "### Permisos")
        for name in yaml.safe_load(read("action.yml"))["outputs"]:
            assert f"| `{name}` |" in doc, name

    def test_every_cli_option_is_documented(self):
        import typer.main

        from secscan import cli

        doc = self.doc("configuration")
        group = typer.main.get_command(cli.app)
        missing = []
        for command in group.commands.values():
            for param in command.params:
                for option in getattr(param, "opts", []) + getattr(param, "secondary_opts", []):
                    if option.startswith("-") and option != "--help" and option not in doc:
                        missing.append(f"{command.name} {option}")
        assert not missing, missing

    def test_the_numeric_limits_in_the_docs_are_the_ones_in_the_code(self):
        from secscan.cli import MAX_SIGNATURE
        from secscan.hostile import MAX_HITS
        from secscan.runners.base import TIMEOUT_SECONDS
        from secscan.runners.zap import MAX_URLS

        config, limits = self.doc("configuration"), self.doc("limitations")
        assert f"hasta {MAX_SIGNATURE} caracteres" in config
        assert f"hasta {MAX_HITS}" in config and f"hasta {MAX_HITS}" in self.doc("design")
        assert f"**{TIMEOUT_SECONDS // 60} minutos**" in limits and f"«superó {TIMEOUT_SECONDS}s»" in limits
        assert f"(hasta {MAX_URLS})" in limits

    def test_the_minutes_range_is_documented_as_the_cli_enforces_it(self):
        import typer.main

        from secscan import cli

        web = typer.main.get_command(cli.app).commands["web"]
        minutes = next(p for p in web.params if p.name == "minutes")
        assert (minutes.type.min, minutes.type.max, minutes.default) == (1, 30, 1)
        assert "de 1 a 30" in self.doc("configuration") and "(de 1 a 30)" in self.doc("limitations")

    def test_the_default_for_fail_on_and_tools_are_the_documented_ones(self):
        import typer.main

        from secscan import cli

        scan = typer.main.get_command(cli.app).commands["scan"]
        defaults = {p.name: p.default for p in scan.params}
        config = self.doc("configuration")

        assert str(defaults["fail_on"].value if hasattr(defaults["fail_on"], "value") else defaults["fail_on"]) == "high"
        assert "| `--fail-on` |" in config and "| `high` |" in "\n".join(l for l in config.splitlines() if "--fail-on" in l)
        assert defaults["tools"] == "gitleaks,semgrep,trivy" and "las tres" in config

    def test_the_exit_codes_are_the_ones_the_cli_uses(self):
        doc = self.doc("configuration")
        for code in ("| 0 |", "| 1 |", "| 2 |"):
            assert code in doc
