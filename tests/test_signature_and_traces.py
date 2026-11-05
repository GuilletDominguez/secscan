"""Quién firma los informes (lo decide quien instala la herramienta) y que el repositorio no guarde rastros."""

import json
import re
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secscan import cli
from secscan.models import ScanResult
from secscan.report_html import to_html
from secscan.report_md import to_markdown

ROOT = Path(__file__).resolve().parent.parent


class TestSignature:
    runner = CliRunner()

    def invoke(self, monkeypatch, tmp_path, *args):
        monkeypatch.setattr(cli, "scan", lambda *a, **k: ScanResult(target="/x/repo"))
        return self.runner.invoke(cli.app, ["scan", str(tmp_path), "--fail-on", "none", *args])

    def test_nobody_signs_by_default(self, monkeypatch, tmp_path):
        for fmt in ("md", "html", "json"):
            out = self.invoke(monkeypatch, tmp_path, "--format", fmt)
            assert out.exit_code == 0 and "firmado por" not in out.stdout

        assert json.loads(self.invoke(monkeypatch, tmp_path, "--format", "json").stdout)["signed_by"] == ""

    def test_the_person_running_it_signs_markdown_html_and_json(self, monkeypatch, tmp_path):
        md = self.invoke(monkeypatch, tmp_path, "--format", "md", "--signed-by", "Equipo de Seguridad").stdout
        html = self.invoke(monkeypatch, tmp_path, "--format", "html", "--signed-by", "Equipo de Seguridad").stdout
        data = json.loads(self.invoke(monkeypatch, tmp_path, "--format", "json", "--signed-by", "Equipo de Seguridad").stdout)

        assert "Informe firmado por **Equipo de Seguridad**." in md
        assert "Informe firmado por <strong>Equipo de Seguridad</strong>" in html
        assert data["signed_by"] == "Equipo de Seguridad"

    def test_report_dir_files_carry_the_signature(self, monkeypatch, tmp_path):
        target = tmp_path / "informe"
        self.invoke(monkeypatch, tmp_path, "--report-dir", str(target), "--signed-by", "Ana")

        for name in ("secscan-report.md", "secscan-report.html", "secscan-report.json"):
            assert "Ana" in (target / name).read_text(encoding="utf-8")

    def test_the_signature_is_escaped(self):
        hostile = ScanResult(target="x", signed_by="<script>alert(1)</script> @alguien")

        assert "<script>" not in to_html(hostile) and "&lt;script&gt;" in to_html(hostile)
        md = to_markdown(hostile)
        assert "<script>" not in md and not re.search(r"@(?!\u200b)\w", md)

    @pytest.mark.parametrize("value", ["a\nb", "a\tb", "x" * 101, "a\x00b"])
    def test_a_signature_with_newlines_control_characters_or_too_long_is_rejected(self, monkeypatch, tmp_path, value):
        out = self.invoke(monkeypatch, tmp_path, "--signed-by", value)
        assert out.exit_code == 2

    def test_it_is_trimmed(self, monkeypatch, tmp_path):
        out = self.invoke(monkeypatch, tmp_path, "--format", "json", "--signed-by", "  Ana  ")
        assert json.loads(out.stdout)["signed_by"] == "Ana"

    def test_web_and_image_commands_accept_it_too(self, monkeypatch):
        monkeypatch.setattr(cli, "scan_image", lambda image, config: ScanResult(target=image))
        out = self.runner.invoke(cli.app, ["image", "app:1", "--format", "md", "--signed-by", "Ana", "--fail-on", "none"])

        assert out.exit_code == 0 and "firmado por **Ana**" in out.stdout

    def test_the_action_has_a_signed_by_input_that_is_empty_by_default_and_travels_through_the_environment(self):
        import yaml

        action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
        scan = next(s for s in action["runs"]["steps"] if s.get("id") == "scan")

        assert action["inputs"]["signed-by"]["default"] == ""
        assert scan["env"]["INPUT_SIGNED_BY"] == "${{ inputs.signed-by }}"
        assert '--signed-by "$INPUT_SIGNED_BY"' in scan["run"] and "${{" not in scan["run"]


def tracked_text_files():
    """Todos los ficheros de texto del proyecto, tengan o no commit (sin .venv, .git ni cachés)."""
    skip = {".venv", ".git", ".pytest_cache", "__pycache__", ".ruff_cache"}
    for path in ROOT.rglob("*"):
        if path.is_file() and not skip & set(path.relative_to(ROOT).parts) and path.name != "uv.lock":
            try:
                yield path, path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue


class TestNoTraces:
    """El proyecto va «hueco»: nada de quien lo escribió ni de ningún repositorio analizado."""

    def test_there_are_files_to_check(self):
        assert len(list(tracked_text_files())) > 30

    @staticmethod
    def own_identity():
        """Lo que identifica a QUIEN EJECUTA los tests: su ruta personal y su identidad de git."""
        import getpass

        found = {str(Path.home()), "/tmp/" + "claude"}  # por partes: así este fichero no se encuentra a sí mismo
        for key in ("user.name", "user.email"):
            done = subprocess.run(["git", "config", key], capture_output=True, text=True)
            if done.returncode == 0 and len(done.stdout.strip()) >= 4:
                found.add(done.stdout.strip())
        user = getpass.getuser()
        if len(user) >= 6 and user not in {"runner", "vagrant", "ubuntu", "docker"}:  # nombres genéricos de CI
            found.add(user)
        return found - {"/", "/root"}

    def test_the_project_holds_nothing_that_identifies_whoever_runs_the_tests(self):
        identity = self.own_identity()
        found = [f"{p.relative_to(ROOT)}: {item}" for p, text in tracked_text_files() for item in identity if item in text]
        assert not found, found

    def test_no_email_addresses(self):
        email = re.compile(r"[\w.+-]+@(?:[\w-]+\.)+[A-Za-z]{2,}\b")
        found = []
        for p, text in tracked_text_files():
            # Las URL con «usuario@host» son vectores de prueba (el truco del usuario en la URL), no correos.
            without_urls = re.sub(r"[A-Za-z][\w+.-]*://\S+", " ", text)
            found += [f"{p.relative_to(ROOT)}: {m.group(0)}" for m in email.finditer(without_urls)]
        assert not found, found

    def test_no_author_or_maintainer_identity_in_the_metadata(self):
        import tomllib

        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        assert "authors" not in project and "maintainers" not in project
        assert "author" not in (ROOT / "action.yml").read_text(encoding="utf-8").split("inputs:")[0].lower().replace("authorization", "")

    def test_fixtures_hold_no_paths_from_real_projects(self):
        # Rutas con el punto de montaje interno o el proyecto de ejemplo; nunca la estructura de un repo real.
        for name in ("gitleaks.json", "semgrep.sarif"):
            text = (ROOT / "tests" / "fixtures" / name).read_text(encoding="utf-8")
            paths = set(re.findall(r'(?:File|uri)"?: "([^"]+)"', text))
            assert paths and all(p.startswith("/target/") for p in paths), (name, paths)
            assert all(re.fullmatch(r"/target/(app|tests)/\w+\.py", p) for p in paths), (name, paths)



def git(*args, cwd):
    import os

    env = {"PATH": os.environ["PATH"], "HOME": str(cwd), "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, env=env)


class TestReportsAreNeverCommitted:
    """Los informes contienen hallazgos de los repos analizados: se quedan en local."""

    runner = CliRunner()

    def run_in(self, monkeypatch, repo, *args):
        monkeypatch.setattr(cli, "scan", lambda *a, **k: ScanResult(target=str(repo)))
        return self.runner.invoke(cli.app, ["scan", str(repo), "--fail-on", "none", *args])

    def test_the_report_dir_ignores_itself(self, monkeypatch, tmp_path):
        out = self.run_in(monkeypatch, tmp_path, "--report-dir", str(tmp_path / "informe"))

        assert out.exit_code == 0
        assert (tmp_path / "informe" / ".gitignore").read_text(encoding="utf-8").splitlines()[-1] == "*"

    def test_git_sees_nothing_to_commit_after_a_report_dir_inside_a_repo(self, monkeypatch, tmp_path):
        git("init", "-q", cwd=tmp_path)
        (tmp_path / "app.py").write_text("x = 1\n")
        self.run_in(monkeypatch, tmp_path, "--report-dir", str(tmp_path / "mis-informes"))
        git("add", "-A", cwd=tmp_path)

        staged = git("diff", "--cached", "--name-only", cwd=tmp_path).stdout.split()
        assert staged == ["app.py"]  # ni los informes ni la carpeta
        assert git("status", "--porcelain", "--ignored", cwd=tmp_path).stdout.count("mis-informes") == 1  # ignorada, no ausente

    def test_an_existing_gitignore_in_the_report_dir_is_left_alone(self, monkeypatch, tmp_path):
        folder = tmp_path / "informe"
        folder.mkdir()
        (folder / ".gitignore").write_text("lo-mio\n", encoding="utf-8")
        self.run_in(monkeypatch, tmp_path, "--report-dir", str(folder))

        assert (folder / ".gitignore").read_text(encoding="utf-8") == "lo-mio\n"

    def test_this_projects_gitignore_covers_every_report_the_tool_writes(self):
        from secscan.cli import REPORT_FILES

        for name in (*REPORT_FILES, "informe/x", "informe-web/x", "secscan-report/x"):
            if name == ".gitignore":
                continue
            done = git("check-ignore", "-q", name, cwd=ROOT)
            assert done.returncode == 0, f"{name} no está en .gitignore"

    def test_but_the_sarif_fixture_stays_versionable(self):
        assert git("check-ignore", "-q", "tests/fixtures/semgrep.sarif", cwd=ROOT).returncode == 1
