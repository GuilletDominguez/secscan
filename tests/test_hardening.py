"""Red de los contenedores, historial de Gitleaks, cobertura de Semgrep y ficheros ilegibles."""

import json
import subprocess
from pathlib import Path

import pytest

from secscan.preflight import unreadable_paths, unreadable_warning
from secscan.runners.base import Runner
from secscan.runners.gitleaks import GitleaksRunner
from secscan.runners.semgrep import SemgrepRunner
from secscan.runners.trivy import TrivyRunner


def docker_command(monkeypatch, tmp_path, runner: Runner) -> list[str]:
    """Captura el comando `docker run` que se lanzaría, sin ejecutar nada."""
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    runner._docker(tmp_path, tmp_path)
    return captured["command"]


class TestNetwork:
    def test_gitleaks_runs_without_network(self, monkeypatch, tmp_path):
        command = docker_command(monkeypatch, tmp_path, GitleaksRunner())
        assert command[command.index("--network") + 1] == "none"

    def test_semgrep_and_trivy_keep_the_network_they_need_for_rules_and_databases(self, monkeypatch, tmp_path):
        for runner in (SemgrepRunner(), TrivyRunner()):
            assert "--network" not in docker_command(monkeypatch, tmp_path, runner)

    def test_containers_never_run_as_root_and_the_repo_is_read_only(self, monkeypatch, tmp_path):
        command = docker_command(monkeypatch, tmp_path, SemgrepRunner())

        assert command[command.index("--user") + 1] != "0:0"
        assert any(arg.endswith(":/target:ro") for arg in command)


class TestGitleaksHistory:
    def test_working_tree_only_by_default(self):
        assert "--no-git" in GitleaksRunner().args()

    def test_history_mode_reads_the_commits(self):
        assert "--no-git" not in GitleaksRunner(history=True).args()

    def test_the_commit_is_shown_in_the_description(self):
        from secscan.runners.gitleaks import parse_gitleaks

        item = {"RuleID": "r", "File": "/target/a.py", "StartLine": 1, "EndLine": 1, "Commit": "0123456789abcdef"}
        assert "commit 01234567" in parse_gitleaks([item])[0].description


class TestSemgrepCoverage:
    def test_lists_the_files_that_were_scanned(self, tmp_path):
        (tmp_path / "semgrep.json").write_text(json.dumps({"paths": {"scanned": ["/target/b.py", "/target/a/x.py"]}}))
        assert SemgrepRunner._scanned(tmp_path) == ["a/x.py", "b.py"]

    def test_falls_back_to_generic_coverage_without_the_json(self, tmp_path):
        assert SemgrepRunner._scanned(tmp_path) == ["."]
        (tmp_path / "semgrep.json").write_text("{}")
        assert SemgrepRunner._scanned(tmp_path) == ["."]


class TestUnreadable:
    def test_nothing_to_report_in_a_normal_tree(self, tmp_path):
        (tmp_path / "ok.py").write_text("x")
        assert unreadable_paths(tmp_path) == [] and unreadable_warning(tmp_path) == []

    def test_reports_files_and_directories_that_cannot_be_read(self, tmp_path):
        (tmp_path / "ok.py").write_text("x")
        secret = tmp_path / "secreto.env"
        secret.write_text("x")
        secret.chmod(0o000)
        locked = tmp_path / "privado"
        locked.mkdir()
        (locked / "dentro.py").write_text("x")
        locked.chmod(0o000)
        try:
            found = unreadable_paths(tmp_path)
            warning = unreadable_warning(tmp_path)[0]
        finally:  # que pytest pueda limpiar el directorio temporal
            locked.chmod(0o755)
            secret.chmod(0o644)

        assert found == ["privado", "secreto.env"]
        assert "2 ruta(s)" in warning and "secreto.env" in warning

    def test_symlinks_are_not_followed_or_reported(self, tmp_path):
        (tmp_path / "roto").symlink_to(tmp_path / "no-existe")
        assert unreadable_paths(tmp_path) == []


class TestUntrustedGitConfig:
    """En modo historial, la configuración de git del repo escaneado no debe poder ejecutar comandos."""

    def test_history_disables_textconv_and_external_diff_but_keeps_all_branches(self):
        args = GitleaksRunner(history=True).args()
        log_opts = args[args.index("--log-opts") + 1].split()

        assert {"--no-textconv", "--no-ext-diff", "--no-show-signature", "--all", "--full-history"} <= set(log_opts)

    def test_git_does_not_load_global_or_system_config(self, monkeypatch, tmp_path):
        command = docker_command(monkeypatch, tmp_path, GitleaksRunner(history=True))

        assert "GIT_CONFIG_NOSYSTEM=1" in command and "GIT_CONFIG_GLOBAL=/dev/null" in command

    def test_program_running_git_settings_are_overridden_from_the_environment(self):
        from secscan.runners.gitleaks import NEUTRALIZED_GIT_CONFIG, git_env

        env = git_env()
        pairs = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"] for i in range(int(env["GIT_CONFIG_COUNT"]))}

        assert pairs == NEUTRALIZED_GIT_CONFIG
        assert pairs["core.fsmonitor"] == "false" and pairs["gpg.program"] == "false"
        assert pairs["log.showSignature"] == "false" and pairs["diff.external"] == ""


def git(*args, cwd, env=None):
    import os

    base = {"PATH": os.environ["PATH"], "HOME": str(cwd), "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, env={**base, **(env or {})})


def docker_has_gitleaks_image() -> bool:
    try:
        return subprocess.run(["docker", "image", "inspect", GitleaksRunner.image], capture_output=True).returncode == 0
    except FileNotFoundError:
        return False


class TestCleanClone:
    def test_requires_a_real_git_directory(self, tmp_path):
        import pytest

        from secscan.gitutil import ensure_git_repo
        from secscan.runners.base import RunnerError

        with pytest.raises(RunnerError, match="repositorio git"):
            ensure_git_repo(tmp_path)  # sin .git
        (tmp_path / ".git").write_text("gitdir: /otro/sitio\n")
        with pytest.raises(RunnerError):
            ensure_git_repo(tmp_path)  # .git como fichero (worktree)

    def test_a_symlinked_git_directory_is_rejected(self, tmp_path):
        import pytest

        from secscan.gitutil import ensure_git_repo
        from secscan.runners.base import RunnerError

        elsewhere = tmp_path / "otro"
        elsewhere.mkdir()
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").symlink_to(elsewhere)
        with pytest.raises(RunnerError):
            ensure_git_repo(repo)

    def test_the_clone_runs_in_the_container_without_network_and_read_only(self, monkeypatch, tmp_path):
        from secscan.gitutil import CLONE_ARGS

        captured = {}

        def fake_run(command, **kwargs):
            captured["command"] = command
            return subprocess.CompletedProcess(command, 0, "", "")

        monkeypatch.setattr(subprocess, "run", fake_run)
        GitleaksRunner(history=True)._docker(tmp_path, tmp_path, args=CLONE_ARGS, entrypoint="git")
        command = captured["command"]

        assert command[command.index("--network") + 1] == "none"
        assert command[command.index("--entrypoint") + 1] == "git"
        assert any(arg.endswith(":/target:ro") for arg in command)
        assert command[command.index("--user") + 1] != "0:0"
        assert command[-len(CLONE_ARGS):] == CLONE_ARGS

    def test_history_mode_scans_the_mirror_not_the_original(self, monkeypatch, tmp_path):
        from secscan.runners.base import Runner, RunnerOutput

        (tmp_path / ".git").mkdir()
        scanned, cloned = [], []
        monkeypatch.setattr(Runner, "_docker", lambda self, target, out, args=None, entrypoint=None: cloned.append(args))
        monkeypatch.setattr(Runner, "run", lambda self, target: scanned.append(target) or RunnerOutput())

        GitleaksRunner(history=True).run(tmp_path)

        assert cloned and cloned[0][0] == "clone"
        assert scanned[0] != tmp_path and scanned[0].name == "repo.git"

    def test_working_tree_mode_still_scans_the_original(self, monkeypatch, tmp_path):
        from secscan.runners.base import Runner, RunnerOutput

        scanned = []
        monkeypatch.setattr(Runner, "run", lambda self, target: scanned.append(target) or RunnerOutput())

        GitleaksRunner().run(tmp_path)

        assert scanned == [tmp_path]

    @pytest.mark.skipif(not docker_has_gitleaks_image(), reason="necesita Docker y la imagen de Gitleaks")
    def test_a_hostile_git_config_runs_nothing_while_cloning_in_the_container(self, tmp_path):
        """El script hostil vive DENTRO del repo (única ruta que existe en el contenedor) y deja un
        marcador en /out, que sí podemos mirar. Primero se comprueba que sin defensas el ataque funciona."""
        from secscan.gitutil import CLONE_ARGS, MIRROR_NAME

        repo = tmp_path / "repo"
        repo.mkdir()
        git("init", "-q", cwd=repo)
        (repo / "evil.sh").write_text("#!/bin/sh\ntouch /out/EJECUTADO\ncat \"$@\"\n")
        (repo / "evil.sh").chmod(0o755)
        (repo / "a.txt").write_text("hola\n")
        git("add", ".", cwd=repo)
        git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "x", cwd=repo)
        with (repo / ".git" / "config").open("a") as config:
            config.write("[core]\n\tfsmonitor = /target/evil.sh\n")

        runner = GitleaksRunner(history=True)
        out = tmp_path / "out"
        out.mkdir()
        runner._docker(repo, out, args=CLONE_ARGS, entrypoint="git")

        assert (out / MIRROR_NAME).is_dir()  # el clon se hizo
        assert not (out / "EJECUTADO").exists()  # y el script del repo no se ejecutó
        assert "evil" not in (out / MIRROR_NAME / "config").read_text()
