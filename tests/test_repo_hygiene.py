"""Lo que hace falta para publicar el repositorio sin sorpresas."""

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def read(name):
    return (ROOT / name).read_text(encoding="utf-8")


def test_the_security_file_offers_no_contact_channel_and_says_the_tool_is_not_an_audit():
    text = read("SECURITY.md")

    assert "uso libre" in text and "No es una auditoría" in text and "sin garantía" in text
    # Nadie a quien avisar: ni correo ni canal privado de GitHub.
    assert "@" not in text and "mailto:" not in text and "Report a vulnerability" not in text


def test_contributing_is_short_and_keeps_the_rules_the_tests_enforce():
    text = read("CONTRIBUTING.md")

    for rule in ("inventados", "pull_request_target", "fijadas por commit", "se escapa"):
        assert rule in text, rule
    assert len(text.splitlines()) < 25  # unas pocas líneas, no un reglamento


def test_line_endings_are_normalized_and_fixtures_are_marked_as_generated():
    text = read(".gitattributes")
    assert "* text=auto eol=lf" in text and "tests/fixtures/** linguist-generated=true" in text


def test_the_readme_explains_requirements_and_where_it_was_tested():
    text = read("README.md")

    for fragment in ("## Requisitos e instalación", "**Docker**", "Probado solo en Linux", "## Uso libre", "SECURITY.md", "CONTRIBUTING.md"):
        assert fragment in text, fragment


def test_the_package_metadata_makes_no_claim_it_cannot_back():
    project = tomllib.loads(read("pyproject.toml"))["project"]

    assert "Operating System :: POSIX :: Linux" in project["classifiers"]
    assert not any("Windows" in c or "MacOS" in c for c in project["classifiers"])  # no se ha probado
    assert "authors" not in project and "urls" not in project  # sin identidad ni enlaces personales


def test_nothing_is_published_that_a_fresh_clone_would_not_need():
    gitignore = read(".gitignore").splitlines()
    for pattern in (".venv/", "__pycache__/", ".pytest_cache/", "secscan-report.md", "informe/"):
        assert pattern in gitignore, pattern
