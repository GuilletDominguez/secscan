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

    for fragment in ("## Requisitos e instalación", "**Docker**", "Probado solo en Linux", "## Licencia y uso libre", "(LICENSE)"):
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
