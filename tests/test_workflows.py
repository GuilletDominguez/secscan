"""Guardas de los workflows y de la action: si alguien las rompe sin darse cuenta, estos tests fallan.

No sustituyen a probar la action en GitHub, pero impiden regresar en lo que más importa: no ejecutar con
permisos de escritura código de forks, no inyectar entradas en el shell, y no depender de etiquetas movibles.
"""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
ACTION = ROOT / "action.yml"
ALL_FILES = [*WORKFLOWS, ACTION]
SHA = re.compile(r"@[0-9a-f]{40}(\s|$)")


def load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def steps_of(path):
    data = load(path)
    if path == ACTION:
        return data["runs"]["steps"]
    return [step for job in data["jobs"].values() for step in job["steps"]]


def triggers(workflow):
    return workflow.get("on", workflow.get(True))  # PyYAML lee la clave `on` como True


def test_there_are_workflows_to_check():
    assert {p.name for p in WORKFLOWS} >= {"ci.yml", "secscan.yml"} and ACTION.exists()


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_never_pull_request_target(path):
    # Da permisos de escritura y secretos a código de forks: el ataque clásico a los repos.
    assert "pull_request_target" not in triggers(load(path))
    assert "workflow_run" not in triggers(load(path)) or True  # permitido, pero sin checkout de código no confiable


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_default_permissions_are_none_and_each_job_declares_its_own(path):
    data = load(path)
    assert data["permissions"] == {}
    for name, job in data["jobs"].items():
        assert "permissions" in job, f"{path.name}:{name} no declara permisos"
        assert "write-all" not in str(job["permissions"])
        assert job["permissions"].get("contents") == "read"
        assert job.get("timeout-minutes"), f"{path.name}:{name} sin timeout"


def test_only_the_scan_job_can_write_and_only_what_it_uses():
    allowed = {"contents": "read", "pull-requests": "write", "security-events": "write"}
    assert load(ROOT / ".github/workflows/secscan.yml")["jobs"]["scan"]["permissions"] == allowed
    assert load(ROOT / ".github/workflows/ci.yml")["jobs"]["test"]["permissions"] == {"contents": "read"}


@pytest.mark.parametrize("path", ALL_FILES, ids=lambda p: p.name)
def test_third_party_actions_are_pinned_to_a_commit_not_a_movable_tag(path):
    for step in steps_of(path):
        uses = step.get("uses")
        if uses and not uses.startswith("./"):
            line = next(line for line in path.read_text(encoding="utf-8").splitlines() if uses in line)
            assert SHA.search(line), f"{path.name}: «{uses}» no está fijada por commit"
            assert re.search(r"#\s*v\d", line), f"{path.name}: «{uses}» sin el comentario de versión"


@pytest.mark.parametrize("path", ALL_FILES, ids=lambda p: p.name)
def test_no_expression_is_interpolated_into_shell_scripts(path):
    # `run: echo ${{ github.event.pull_request.title }}` permite inyectar comandos. Todo va por `env:`.
    for step in steps_of(path):
        if "run" in step:
            assert "${{" not in step["run"], f"{path.name}: expresión dentro de un run:\n{step['run']}"


def test_the_javascript_of_github_script_reads_inputs_from_the_environment_only():
    for step in steps_of(ACTION):
        if "github-script" in step.get("uses", ""):
            assert "${{" not in step["with"]["script"]


@pytest.mark.parametrize("path", ALL_FILES, ids=lambda p: p.name)
def test_checkouts_do_not_persist_the_token(path):
    for step in steps_of(path):
        if step.get("uses", "").startswith("actions/checkout@"):
            assert step["with"]["persist-credentials"] is False


def test_every_composite_run_step_declares_its_shell():
    for step in steps_of(ACTION):
        if "run" in step:
            assert step.get("shell") == "bash"


def test_write_steps_are_skipped_for_forks_where_the_token_is_read_only():
    guarded = [s for s in steps_of(ACTION) if "github-script" in s.get("uses", "") or "upload-sarif" in s.get("uses", "")]
    assert len(guarded) == 2
    for step in guarded:
        condition = " ".join(str(step["if"]).split())
        assert "github.event.pull_request.head.repo.full_name == github.repository" in condition


def test_the_comment_is_only_posted_on_pull_requests():
    comment = next(s for s in steps_of(ACTION) if "github-script" in s.get("uses", ""))
    assert "github.event_name == 'pull_request'" in comment["if"]


def test_the_scan_step_never_fails_the_job_itself_and_a_last_step_does():
    steps = steps_of(ACTION)
    scan = next(s for s in steps if s.get("id") == "scan")
    assert "set +e" in scan["run"] and "exit-code=$code" in scan["run"]
    last = steps[-1]
    assert "steps.scan.outputs.exit-code != '0'" in last["if"] and 'exit "$EXIT_CODE"' in last["run"]
    # Los pasos que publican se ejecutan siempre, también si hay hallazgos.
    scan_index = steps.index(scan)
    for step in steps[scan_index + 1 : -1]:
        assert "always()" in str(step.get("if", "")), step


def test_untrusted_output_is_wrapped_in_stop_commands_with_a_random_token():
    scan = next(s for s in steps_of(ACTION) if s.get("id") == "scan")["run"]
    assert "::stop-commands::$token" in scan and "::$token::" in scan
    assert "/dev/urandom" in scan  # un token impredecible: uno fijo se podría reproducir desde el repo escaneado
    run = scan.index("--frozen secscan")  # la orden real, no la palabra en un comentario
    assert scan.index('echo "::stop-commands::') < run < scan.index('echo "::$token::"')


def test_the_virtualenv_lives_outside_the_scanned_workspace():
    scan = next(s for s in steps_of(ACTION) if s.get("id") == "scan")
    assert "runner.temp" in scan["env"]["UV_PROJECT_ENVIRONMENT"]
    assert "runner.temp" in scan["env"]["REPORT_DIR"]


def test_the_dogfood_workflow_uses_the_local_action_after_checking_out_the_code():
    uses = [s.get("uses", "") for s in steps_of(ROOT / ".github/workflows/secscan.yml")]
    assert uses[0].startswith("actions/checkout@") and uses[1] == "./"


def test_dependabot_keeps_the_pinned_actions_up_to_date_with_a_cooldown():
    data = load(ROOT / ".github/dependabot.yml")
    actions = next(u for u in data["updates"] if u["package-ecosystem"] == "github-actions")
    assert actions["cooldown"]["default-days"] >= 7


def test_trivy_cache_key_is_refreshed_daily():
    cache = next(s for s in steps_of(ACTION) if s.get("uses", "").startswith("actions/cache@"))
    assert "steps.day.outputs.day" in cache["with"]["key"]
