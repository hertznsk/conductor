"""Tests for the ``--environment`` flag on run/resume/validate (execution profiles).

Covers:
- run/resume forward the resolved environment to the engine constructor
- the flag passes through to the detached ``--web-bg`` child argv (both the
  run and the resume builders), with ``~`` path expansion before forwarding
- dry-run resolves the environment at engine construction (fail-fast) without
  changing the plan output
- CLI-level failure path: an unresolvable environment name exits 1 and lists
  the searched locations

All tests are module-level functions so the plan's node ids resolve verbatim.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from conductor.cli.app import app
from conductor.engine.checkpoint import CheckpointManager

runner = CliRunner()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# A provider-free workflow: a single set step, no LLM required.
_PLAIN_SET_YAML = """\
workflow:
  name: omo-ep-plain
  entry_point: mark
agents:
  - name: mark
    type: set
    value: "'ok'"
    routes:
      - to: $end
output:
  result: "{{ mark.output }}"
"""

# A valid project-level environment document for the fixture workflow.
_ENV_YAML = """\
default: shell
profiles:
  shell:
    backend: local
"""


def _write_workflow(tmp_path: Path) -> Path:
    """Write the provider-free fixture workflow and return its path."""
    wf = tmp_path / "plain-set.yaml"
    wf.write_text(_PLAIN_SET_YAML, encoding="utf-8")
    return wf


def _write_environment(tmp_path: Path, name: str = "demo") -> Path:
    """Write a project-level environment document next to the workflow."""
    env_dir = tmp_path / ".conductor" / "environments"
    env_dir.mkdir(parents=True)
    env_path = env_dir / f"{name}.yaml"
    env_path.write_text(_ENV_YAML, encoding="utf-8")
    return env_path


def _write_checkpoint(tmp_path: Path, workflow_path: Path) -> Path:
    """Write a minimal checkpoint for the fixture workflow (mirrors test_resume_command)."""
    checkpoint = {
        "version": 1,
        "workflow_path": str(workflow_path.resolve()),
        "workflow_hash": CheckpointManager.compute_workflow_hash(workflow_path),
        "created_at": "2026-02-24T15:30:00+00:00",
        "failure": {
            "error_type": "ProviderError",
            "message": "Network error",
            "agent": "mark",
            "iteration": 1,
        },
        "inputs": {},
        "current_agent": "mark",
        "context": {
            "workflow_inputs": {},
            "agent_outputs": {},
            "current_iteration": 0,
            "execution_history": [],
        },
        "limits": {
            "current_iteration": 0,
            "max_iterations": 10,
            "execution_history": [],
        },
        "copilot_session_ids": {},
        "run_id": "",
        "event_log_path": "",
    }
    cp_path = tmp_path / f"{workflow_path.stem}-20260224-153000.json"
    cp_path.write_text(json.dumps(checkpoint, indent=2), encoding="utf-8")
    return cp_path


def _patched_bg_spawn(pid: int, port: int) -> tuple:
    """Patches for the bg launch gate so the child argv can be inspected without a real fork.

    Returns four context managers; enter the first one as ``mock_spawn`` and
    after exit ``mock_spawn.call_args.args[0]`` holds the child argv.
    """
    fake_proc = MagicMock(pid=pid)
    fake_proc.poll.return_value = None
    return (
        patch("conductor.cli.bg_runner._spawn_detached", return_value=fake_proc),
        patch("conductor.cli.bg_runner._wait_for_server", return_value=True),
        patch(
            "conductor.fleet.records.read_run_record",
            return_value=MagicMock(pid=pid, mode="bg", port=port),
        ),
        patch("conductor.cli.bg_runner._resolve_start_timeout", return_value=0.0),
    )


def _mock_registry_and_engine(
    mock_registry_cls: MagicMock, mock_engine_cls: MagicMock, method: str
) -> None:
    """Wire the two standard mocks: an async-capable ProviderRegistry and an engine
    whose ``method`` (run/resume) returns a fixed result."""
    mock_registry = AsyncMock()
    mock_registry_cls.return_value = mock_registry
    mock_registry.__aenter__ = AsyncMock(return_value=mock_registry)
    mock_registry.__aexit__ = AsyncMock(return_value=False)

    mock_engine = MagicMock()
    setattr(mock_engine, method, AsyncMock(return_value={"result": "ok"}))
    mock_engine.config.workflow.cost.show_summary = False
    mock_engine_cls.return_value = mock_engine


# ---------------------------------------------------------------------------
# run/resume forward the resolved environment to the engine constructor
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_forwards_environment_to_engine(tmp_path: Path) -> None:
    """Requirement: run_workflow_async resolves --environment and passes it to the
    engine constructor as ``execution_environment``."""
    from conductor.cli.run import run_workflow_async

    wf_path = _write_workflow(tmp_path)
    _write_environment(tmp_path)

    with (
        patch("conductor.cli.run.ProviderRegistry") as mock_registry_cls,
        patch("conductor.cli.run.WorkflowEngine") as mock_engine_cls,
    ):
        _mock_registry_and_engine(mock_registry_cls, mock_engine_cls, "run")

        await run_workflow_async(wf_path, {}, environment="demo")

    ctor_kwargs = mock_engine_cls.call_args.kwargs
    resolved = ctor_kwargs["execution_environment"]
    assert resolved is not None
    assert resolved.name == "demo"
    assert resolved.source == "project"
    assert resolved.document.default == "shell"


@pytest.mark.asyncio
async def test_run_without_environment_passes_none(tmp_path: Path) -> None:
    """Requirement: without --environment the engine receives no execution
    environment (built-in local/default applies)."""
    from conductor.cli.run import run_workflow_async

    wf_path = _write_workflow(tmp_path)

    with (
        patch("conductor.cli.run.ProviderRegistry") as mock_registry_cls,
        patch("conductor.cli.run.WorkflowEngine") as mock_engine_cls,
    ):
        _mock_registry_and_engine(mock_registry_cls, mock_engine_cls, "run")

        await run_workflow_async(wf_path, {})

    assert mock_engine_cls.call_args.kwargs["execution_environment"] is None


@pytest.mark.asyncio
async def test_resume_forwards_environment_to_engine(tmp_path: Path) -> None:
    """Requirement: resume_workflow_async has run/resume parity — it resolves
    --environment against the resumed workflow's directory and passes it to
    the engine constructor."""
    from conductor.cli.run import resume_workflow_async

    wf_path = _write_workflow(tmp_path)
    _write_environment(tmp_path)
    cp_path = _write_checkpoint(tmp_path, wf_path)

    with (
        patch("conductor.cli.run.ProviderRegistry") as mock_registry_cls,
        patch("conductor.cli.run.WorkflowEngine") as mock_engine_cls,
        patch("conductor.cli.run._write_terminal_record_for_current_process"),
        patch("conductor.cli.run._remove_run_record_for_current_process_safe"),
    ):
        _mock_registry_and_engine(mock_registry_cls, mock_engine_cls, "resume")

        await resume_workflow_async(checkpoint_path=cp_path, environment="demo")

    ctor_kwargs = mock_engine_cls.call_args.kwargs
    resolved = ctor_kwargs["execution_environment"]
    assert resolved is not None
    assert resolved.name == "demo"
    assert resolved.source == "project"


@pytest.mark.asyncio
async def test_run_from_subdirectory_resolves_root_project_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Requirement (PR #551 review, blocking): run invoked from a subdirectory
    with a RELATIVE workflow path must resolve the repository root's project
    environment document — a same-named user document must not win."""
    from conductor.cli.run import run_workflow_async

    repo = tmp_path / "repo"
    sub = repo / "sub"
    sub.mkdir(parents=True)
    (repo / ".git").mkdir()
    env_dir = repo / ".conductor" / "environments"
    env_dir.mkdir(parents=True)
    (env_dir / "prod.yaml").write_text(_ENV_YAML, encoding="utf-8")
    home = tmp_path / "isolated-home"
    (home / "environments").mkdir(parents=True)
    (home / "environments" / "prod.yaml").write_text(
        "default: other\nprofiles:\n  other:\n    backend: local\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CONDUCTOR_HOME", str(home))
    (sub / "plain-set.yaml").write_text(_PLAIN_SET_YAML, encoding="utf-8")

    with (
        patch("conductor.cli.run.ProviderRegistry") as mock_registry_cls,
        patch("conductor.cli.run.WorkflowEngine") as mock_engine_cls,
    ):
        _mock_registry_and_engine(mock_registry_cls, mock_engine_cls, "run")
        monkeypatch.chdir(sub)

        await run_workflow_async(Path("plain-set.yaml"), {}, environment="prod")

    resolved = mock_engine_cls.call_args.kwargs["execution_environment"]
    assert resolved is not None
    assert resolved.source == "project"
    assert resolved.document.default == "shell"


@pytest.mark.asyncio
async def test_run_empty_environment_fails_instead_of_falling_back(
    tmp_path: Path,
) -> None:
    """Requirement (PR #551 review): an explicitly empty --environment (e.g. an
    unset variable forwarded as --environment "$ENVIRONMENT") must reach the
    resolver and fail clearly, not silently use the built-in environment."""
    from conductor.cli.run import run_workflow_async
    from conductor.exceptions import ConfigurationError

    wf_path = _write_workflow(tmp_path)

    with pytest.raises(ConfigurationError, match="non-empty"):
        await run_workflow_async(wf_path, {}, environment="")


@pytest.mark.asyncio
async def test_resume_empty_environment_fails_instead_of_falling_back(
    tmp_path: Path,
) -> None:
    """Requirement (PR #551 review): resume repeats the run fix — an explicitly
    empty --environment fails in the resolver instead of falling back."""
    from conductor.cli.run import resume_workflow_async
    from conductor.exceptions import ConfigurationError

    wf_path = _write_workflow(tmp_path)
    cp_path = _write_checkpoint(tmp_path, wf_path)

    with pytest.raises(ConfigurationError, match="non-empty"):
        await resume_workflow_async(checkpoint_path=cp_path, environment="")


def test_dry_run_empty_environment_fails_instead_of_falling_back(
    tmp_path: Path,
) -> None:
    """Requirement (PR #551 review): dry-run resolves --environment at engine
    construction, so an explicitly empty value fails there too — same as run
    and resume, and same as validate already did."""
    from conductor.cli.run import build_dry_run_plan
    from conductor.exceptions import ConfigurationError

    wf_path = _write_workflow(tmp_path)

    with pytest.raises(ConfigurationError, match="non-empty"):
        build_dry_run_plan(wf_path, environment="")


# ---------------------------------------------------------------------------
# CLI-level flag forwarding
# ---------------------------------------------------------------------------


def test_run_command_forwards_environment(tmp_path: Path) -> None:
    """Requirement: `conductor run --environment X` reaches run_workflow_async."""
    wf_path = _write_workflow(tmp_path)

    with patch("conductor.cli.run.run_workflow_async", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = {"result": "ok"}
        result = runner.invoke(app, ["run", str(wf_path), "--environment", "demo"])

    assert result.exit_code == 0
    assert mock_run.call_args.kwargs["environment"] == "demo"


def test_resume_command_forwards_environment(tmp_path: Path) -> None:
    """Requirement: `conductor resume --environment X` reaches resume_workflow_async."""
    wf_path = _write_workflow(tmp_path)

    with patch("conductor.cli.run.resume_workflow_async", new_callable=AsyncMock) as mock_resume:
        mock_resume.return_value = {"result": "ok"}
        result = runner.invoke(app, ["resume", str(wf_path), "--environment", "demo"])

    assert result.exit_code == 0
    assert mock_resume.call_args.kwargs["environment"] == "demo"


def test_validate_command_forwards_environment(tmp_path: Path) -> None:
    """Requirement: `conductor validate --environment X` reaches validate_workflow."""
    wf_path = _write_workflow(tmp_path)

    with (
        patch("conductor.cli.validate.validate_workflow") as mock_validate,
        patch("conductor.cli.validate.display_validation_success"),
    ):
        mock_validate.return_value = (True, MagicMock())
        result = runner.invoke(app, ["validate", str(wf_path), "--environment", "demo"])

    assert result.exit_code == 0
    assert mock_validate.call_args.kwargs["environment"] == "demo"


def test_run_web_bg_forwards_environment(tmp_path: Path) -> None:
    """Requirement: `conductor run --web-bg --environment X` passes the flag to
    launch_background (which forwards it to the detached child's argv)."""
    wf_path = _write_workflow(tmp_path)

    with patch("conductor.cli.bg_runner.launch_background") as mock_launch:
        mock_launch.return_value = MagicMock(
            still_running=True,
            url="http://127.0.0.1:9999",
            stderr_log=Path("/tmp/x"),
            workflow_started=True,
            run_record_written=True,
        )
        result = runner.invoke(app, ["run", str(wf_path), "--web-bg", "--environment", "demo"])

    assert result.exit_code == 0
    assert mock_launch.call_args.kwargs["environment"] == "demo"


def test_resume_web_bg_forwards_environment(tmp_path: Path) -> None:
    """Requirement: `conductor resume --web-bg --environment X` passes the flag to
    launch_background_resume."""
    wf_path = _write_workflow(tmp_path)

    with patch("conductor.cli.bg_runner.launch_background_resume") as mock_launch:
        mock_launch.return_value = MagicMock(
            still_running=True,
            url="http://127.0.0.1:9999",
            stderr_log=Path("/tmp/x"),
            workflow_started=True,
            run_record_written=True,
        )
        result = runner.invoke(app, ["resume", str(wf_path), "--web-bg", "--environment", "demo"])

    assert result.exit_code == 0
    assert mock_launch.call_args.kwargs["environment"] == "demo"


# ---------------------------------------------------------------------------
# bg argv construction (unit level — no real fork)
# ---------------------------------------------------------------------------


def test_web_bg_run_argv_contains_environment(tmp_path: Path) -> None:
    """Requirement: launch_background puts `--environment <name>` into the child
    argv, following the --provider precedent."""
    from conductor.cli import bg_runner

    wf_path = _write_workflow(tmp_path)
    p1, p2, p3, p4 = _patched_bg_spawn(pid=11, port=9401)
    with p1 as mock_spawn, p2, p3, p4:
        bg_runner.launch_background(
            workflow_path=wf_path,
            inputs={},
            web_port=9401,
            environment="demo",
        )

    cmd = mock_spawn.call_args.args[0]
    env_idx = cmd.index("--environment")
    assert cmd[env_idx + 1] == "demo"
    # A bare name must be forwarded verbatim — no absolutization.
    assert not os.path.isabs(cmd[env_idx + 1])


def test_web_bg_resume_argv_contains_environment(tmp_path: Path) -> None:
    """Requirement: launch_background_resume has argv parity with launch_background."""
    from conductor.cli import bg_runner

    wf_path = _write_workflow(tmp_path)
    p1, p2, p3, p4 = _patched_bg_spawn(pid=12, port=9402)
    with p1 as mock_spawn, p2, p3, p4:
        bg_runner.launch_background_resume(
            workflow_path=wf_path,
            checkpoint_path=None,
            web_port=9402,
            environment="demo",
        )

    cmd = mock_spawn.call_args.args[0]
    env_idx = cmd.index("--environment")
    assert cmd[env_idx + 1] == "demo"


def test_tilde_environment_path_expanded_before_forwarding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Requirement (Oracle O4): a `~` path value is expanduser()-ed and THEN
    absolutized against the launching process's cwd before reaching the child
    argv — in BOTH builders. `abspath("~/x.yaml")` does not expand home."""
    from conductor.cli import bg_runner

    # Anchor `~` at tmp_path and place the document there.
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "env.yaml").write_text(_ENV_YAML, encoding="utf-8")
    expected = os.path.abspath(str(tmp_path / "env.yaml"))
    assert expected == str(tmp_path / "env.yaml")  # tmp_path is already absolute

    wf_path = _write_workflow(tmp_path)

    p1, p2, p3, p4 = _patched_bg_spawn(pid=13, port=9403)
    with p1 as mock_spawn, p2, p3, p4:
        bg_runner.launch_background(
            workflow_path=wf_path,
            inputs={},
            web_port=9403,
            environment="~/env.yaml",
        )
    cmd = mock_spawn.call_args.args[0]
    env_idx = cmd.index("--environment")
    # The argv must carry the absolute expanded path, not "~/env.yaml".
    assert cmd[env_idx + 1] == expected

    p1, p2, p3, p4 = _patched_bg_spawn(pid=14, port=9404)
    with p1 as mock_spawn, p2, p3, p4:
        bg_runner.launch_background_resume(
            workflow_path=wf_path,
            checkpoint_path=None,
            web_port=9404,
            environment="~/env.yaml",
        )
    cmd = mock_spawn.call_args.args[0]
    env_idx = cmd.index("--environment")
    assert cmd[env_idx + 1] == expected


def test_no_environment_flag_absent_from_argv(tmp_path: Path) -> None:
    """Requirement: without an environment, the child argv carries no
    --environment flag at all."""
    from conductor.cli import bg_runner

    wf_path = _write_workflow(tmp_path)
    p1, p2, p3, p4 = _patched_bg_spawn(pid=15, port=9405)
    with p1 as mock_spawn, p2, p3, p4:
        bg_runner.launch_background(
            workflow_path=wf_path,
            inputs={},
            web_port=9405,
        )

    cmd = mock_spawn.call_args.args[0]
    assert "--environment" not in cmd


def test_web_bg_empty_environment_forwarded_verbatim(tmp_path: Path) -> None:
    """Requirement (PR #551 review): an explicitly empty --environment is
    forwarded to the detached child as ["--environment", ""] in BOTH builders,
    so the child fails with the resolver's clear non-empty-string error
    instead of the launcher silently dropping the flag."""
    from conductor.cli import bg_runner

    wf_path = _write_workflow(tmp_path)

    p1, p2, p3, p4 = _patched_bg_spawn(pid=16, port=9406)
    with p1 as mock_spawn, p2, p3, p4:
        bg_runner.launch_background(
            workflow_path=wf_path,
            inputs={},
            web_port=9406,
            environment="",
        )
    cmd = mock_spawn.call_args.args[0]
    env_idx = cmd.index("--environment")
    assert cmd[env_idx + 1] == ""

    p1, p2, p3, p4 = _patched_bg_spawn(pid=17, port=9407)
    with p1 as mock_spawn, p2, p3, p4:
        bg_runner.launch_background_resume(
            workflow_path=wf_path,
            checkpoint_path=None,
            web_port=9407,
            environment="",
        )
    cmd = mock_spawn.call_args.args[0]
    env_idx = cmd.index("--environment")
    assert cmd[env_idx + 1] == ""


# ---------------------------------------------------------------------------
# Dry-run: resolution at ctor (fail-fast) without changing the plan output
# ---------------------------------------------------------------------------


def test_dry_run_invalid_environment_fails_before_plan(tmp_path: Path) -> None:
    """Requirement (Metis R8): dry-run resolves --environment at engine
    construction, so an unresolvable name fails before any plan output."""
    from conductor.cli.run import build_dry_run_plan
    from conductor.exceptions import ConfigurationError

    wf_path = _write_workflow(tmp_path)

    with pytest.raises(ConfigurationError, match="was not found"):
        build_dry_run_plan(wf_path, environment="definitely-missing")


def test_dry_run_plan_output_unchanged_with_valid_environment(tmp_path: Path) -> None:
    """Requirement: a valid --environment compiles the manifest at ctor
    (preflight) but the rendered plan is identical to the no-flag plan."""
    from conductor.cli.run import build_dry_run_plan

    wf_path = _write_workflow(tmp_path)
    _write_environment(tmp_path)

    plan_without = build_dry_run_plan(wf_path)
    plan_with = build_dry_run_plan(wf_path, environment="demo")

    assert plan_without == plan_with


# ---------------------------------------------------------------------------
# CLI-level failure path
# ---------------------------------------------------------------------------


def test_run_with_missing_environment_exits_1_and_lists_searched_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Requirement: `conductor run --environment <missing>` exits 1 and the
    error output lists every location that was searched."""
    wf_path = _write_workflow(tmp_path)
    # A short user-level root keeps the searched-path lines inside the
    # error panel's width, so the list is assertable verbatim.
    monkeypatch.setenv("CONDUCTOR_HOME", "/tmp/ce")

    result = runner.invoke(app, ["run", str(wf_path), "--environment", "definitely-missing"])

    assert result.exit_code == 1
    assert "definitely-missing" in result.output
    assert "Searched:" in result.output
    # The user-level candidate must be enumerated in the output, proving
    # the searched list is rendered and not truncated to the headline.
    assert "/tmp/ce/environments/definitely-missing.yaml" in result.output


def test_run_with_environment_name_outside_charset_exits_1(tmp_path: Path) -> None:
    """Requirement: names outside the [A-Za-z0-9_-]+ charset never reach
    resolution as names — the CLI rejects them with the charset message."""
    wf_path = _write_workflow(tmp_path)

    result = runner.invoke(app, ["run", str(wf_path), "--environment", "bad name"])

    assert result.exit_code == 1
    assert "charset" in result.output.lower() or "A-Za-z0-9" in result.output


def test_run_command_empty_environment_exits_1(tmp_path: Path) -> None:
    """Requirement (PR #551 review): `conductor run --environment ""` exits 1
    with the resolver's non-empty-string error, matching validate — an unset
    variable forwarded as --environment "$ENVIRONMENT" must not silently run
    against the built-in environment."""
    wf_path = _write_workflow(tmp_path)

    result = runner.invoke(app, ["run", str(wf_path), "--environment", ""])

    assert result.exit_code == 1
    assert "non-empty" in result.output


# ---------------------------------------------------------------------------
# Help surface: no square brackets in the new help strings (rule G companion)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("command", ["run", "resume", "validate"])
def test_environment_help_rendered(command: str) -> None:
    """Requirement: --environment shows up in each command's --help and the
    help string survives rich markup parsing (no unescaped brackets)."""
    result = runner.invoke(app, [command, "--help"])
    assert result.exit_code == 0
    assert "--environment" in result.output
    assert "Execution environment" in result.output
