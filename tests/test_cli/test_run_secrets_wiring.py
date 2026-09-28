"""CLI wiring for the run-scoped secret machinery (``run`` and ``resume``).

Covers the CLI-owned lifecycle: environment resolution and secret preflight
happen before the inputs panel and before MCP server construction; the engine
receives the CLI's cache/redactor pair by injection; the redactor is attached
to the emitter and set as the contextvar before any sink can emit; and both
are cleared (with the contextvar restored via token) in the outermost finally.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from conductor import redaction
from conductor.cli.run import _build_mcp_servers
from conductor.config.schema import (
    MCPServerDef,
    RouteDef,
    RuntimeConfig,
    SetStepDef,
    WorkflowConfig,
    WorkflowDef,
)
from conductor.engine.checkpoint import CheckpointManager
from conductor.engine.secrets import SecretValueCache
from conductor.events import WorkflowEvent, WorkflowEventEmitter
from conductor.exceptions import ConfigurationError
from conductor.redaction import REDACTED_MARKER, RunRedactor

_CLI_TOKEN_VAR = "CONDUCTOR_TEST_TASK7_CLI_TOKEN"

_SECRET_WORKFLOW = """\
workflow:
  name: cli-secrets
  entry_point: run
agents:
  - name: run
    type: script
    command: echo
    execution:
      secrets:
        - ref: token
          scope: script
          delivery:
            env: DELIVERED_TOKEN
    routes:
      - to: $end
output:
  result: "{{ run.output.stdout }}"
"""

_PLAIN_WORKFLOW = """\
workflow:
  name: cli-plain
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

_ENV_YAML = """\
default: shell
profiles:
  shell:
    backend: local
secrets:
  token:
    source:
      env: CONDUCTOR_TEST_TASK7_CLI_TOKEN
"""


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep run/terminal records out of the developer's real ``~/.conductor``."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("CONDUCTOR_HOME", str(tmp_path / "conductor-home"))


def _write_workflow(tmp_path: Path, body: str = _SECRET_WORKFLOW) -> Path:
    wf = tmp_path / "workflow.yaml"
    wf.write_text(body, encoding="utf-8")
    return wf


def _write_environment(tmp_path: Path, name: str = "demo") -> Path:
    env_dir = tmp_path / ".conductor" / "environments"
    env_dir.mkdir(parents=True)
    env_path = env_dir / f"{name}.yaml"
    env_path.write_text(_ENV_YAML, encoding="utf-8")
    return env_path


def _write_checkpoint(
    tmp_path: Path, workflow_path: Path, *, event_log_path: Path | None = None
) -> Path:
    """A minimal resumable checkpoint (mirrors test_environment_flag)."""
    checkpoint = {
        "version": 1,
        "workflow_path": str(workflow_path.resolve()),
        "workflow_hash": CheckpointManager.compute_workflow_hash(workflow_path),
        "created_at": "2026-02-24T15:30:00+00:00",
        "failure": {
            "error_type": "ProviderError",
            "message": "Network error",
            "agent": "run",
            "iteration": 1,
        },
        "inputs": {},
        "current_agent": "run",
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
        "event_log_path": str(event_log_path) if event_log_path is not None else "",
    }
    cp_path = tmp_path / f"{workflow_path.stem}-20260224-153000.json"
    cp_path.write_text(json.dumps(checkpoint, indent=2), encoding="utf-8")
    return cp_path


def _mock_registry_and_engine(
    mock_registry_cls: MagicMock,
    mock_engine_cls: MagicMock,
    method: str,
    engine: MagicMock | None = None,
) -> MagicMock:
    """Wire the standard mocks: async ProviderRegistry + fixed-result engine."""
    mock_registry = AsyncMock()
    mock_registry_cls.return_value = mock_registry
    mock_registry.__aenter__ = AsyncMock(return_value=mock_registry)
    mock_registry.__aexit__ = AsyncMock(return_value=False)

    mock_engine = engine or MagicMock()
    setattr(mock_engine, method, AsyncMock(return_value={"result": "ok"}))
    mock_engine.config.workflow.cost.show_summary = False
    mock_engine_cls.return_value = mock_engine
    return mock_engine


@pytest.mark.asyncio
async def test_run_injects_cli_owned_pair_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Requirement: run resolves the environment, prepares the redactor/cache
    # pair, injects both into the engine constructor, and clears them (plus the
    # contextvar) after the run's final sinks drain.
    monkeypatch.setenv(_CLI_TOKEN_VAR, "cli-secret-value-1")
    wf_path = _write_workflow(tmp_path)
    _write_environment(tmp_path)

    from conductor.cli.run import run_workflow_async

    with (
        patch("conductor.cli.run.ProviderRegistry") as mock_registry_cls,
        patch("conductor.cli.run.WorkflowEngine") as mock_engine_cls,
    ):
        _mock_registry_and_engine(mock_registry_cls, mock_engine_cls, "run")
        await run_workflow_async(wf_path, {}, environment="demo")

    kwargs = mock_engine_cls.call_args.kwargs
    cache = kwargs["secret_cache"]
    redactor = kwargs["redactor"]
    assert isinstance(cache, SecretValueCache)
    assert isinstance(redactor, RunRedactor)
    # CLI-owned cleanup ran: the pair is cleared and the contextvar restored.
    assert not redactor.active
    assert redaction.current() is None
    with pytest.raises(ConfigurationError, match="has not been resolved"):
        cache.secret_for("token")


@pytest.mark.asyncio
async def test_run_prepares_secrets_before_inputs_print_and_scrubs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Requirement: the redactor exists BEFORE the inputs panel prints, and the
    # printed panel content is scrubbed of declared secret values.
    secret = "input-secret-value-9"
    monkeypatch.setenv(_CLI_TOKEN_VAR, secret)
    wf_path = _write_workflow(tmp_path)
    _write_environment(tmp_path)

    order: list[str] = []
    printed: list[str] = []

    real_set_redactor = WorkflowEventEmitter.set_redactor

    def spy_set_redactor(self: WorkflowEventEmitter, redactor: RunRedactor | None) -> None:
        order.append("set_redactor")
        return real_set_redactor(self, redactor)

    monkeypatch.setattr(WorkflowEventEmitter, "set_redactor", spy_set_redactor)

    from conductor.cli import run as run_module

    real_section = run_module.verbose_log_section

    def spy_section(title: str, content: str) -> None:
        order.append(f"section:{title}")
        printed.append(content)
        return real_section(title, content)

    monkeypatch.setattr(run_module, "verbose_log_section", spy_section)

    from conductor.cli.run import run_workflow_async

    with (
        patch("conductor.cli.run.ProviderRegistry") as mock_registry_cls,
        patch("conductor.cli.run.WorkflowEngine") as mock_engine_cls,
    ):
        _mock_registry_and_engine(mock_registry_cls, mock_engine_cls, "run")
        await run_workflow_async(wf_path, {"key": secret}, environment="demo")

    assert order.index("set_redactor") < order.index("section:Workflow Inputs")
    inputs_panel = printed[order.index("section:Workflow Inputs") - 1]
    assert secret not in inputs_panel
    assert REDACTED_MARKER in inputs_panel


@pytest.mark.asyncio
async def test_run_secret_preflight_fails_before_mcp_and_engine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Requirement: a broken secret reference (unset source variable) fails at
    # prepare time as ConfigurationError — before _build_mcp_servers and before
    # engine construction — through the existing error path.
    monkeypatch.delenv(_CLI_TOKEN_VAR, raising=False)
    wf_path = _write_workflow(tmp_path)
    _write_environment(tmp_path)

    from conductor.cli.run import run_workflow_async

    with (
        patch("conductor.cli.run.ProviderRegistry"),
        patch("conductor.cli.run.WorkflowEngine") as mock_engine_cls,
        patch("conductor.cli.run._build_mcp_servers", new_callable=AsyncMock) as mock_build,
        pytest.raises(ConfigurationError, match="not set or is empty"),
    ):
        await run_workflow_async(wf_path, {}, environment="demo")

    mock_build.assert_not_called()
    mock_engine_cls.assert_not_called()
    # Cleanup still ran on the failure path.
    assert redaction.current() is None


@pytest.mark.asyncio
async def test_resume_prepares_secrets_before_guidance_and_seeding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Requirement: on the resume path the secret prepare (emitter attach) lands
    # STRICTLY BEFORE --guidance application, the dashboard seeding (prepend +
    # replay + synthetic fallback), and the direct workflow_started JSONL write.
    monkeypatch.setenv(_CLI_TOKEN_VAR, "resume-secret-value")
    wf_path = _write_workflow(tmp_path)
    _write_environment(tmp_path)
    # A real (empty) prior event log so the replay branch is reachable.
    prior_log = tmp_path / "prior.events.jsonl"
    prior_log.write_text("", encoding="utf-8")
    cp_path = _write_checkpoint(tmp_path, wf_path, event_log_path=prior_log)

    order: list[str] = []

    real_set_redactor = WorkflowEventEmitter.set_redactor

    def spy_set_redactor(self: WorkflowEventEmitter, redactor: RunRedactor | None) -> None:
        order.append("set_redactor")
        return real_set_redactor(self, redactor)

    monkeypatch.setattr(WorkflowEventEmitter, "set_redactor", spy_set_redactor)

    engine = MagicMock()
    engine.add_user_guidance = MagicMock(side_effect=lambda *a, **k: order.append("guidance"))
    engine.build_workflow_started_data = AsyncMock(return_value={"name": "cli-secrets"})

    dashboard = MagicMock()
    dashboard.port = 8080
    dashboard.url = "http://127.0.0.1:8080"
    dashboard.start = AsyncMock()
    dashboard.stop = AsyncMock()
    dashboard.wait_for_stop = AsyncMock()
    dashboard.wait_for_clients_disconnect = AsyncMock()
    dashboard.prepend_workflow_started = MagicMock(
        side_effect=lambda *a, **k: order.append("prepend")
    )
    dashboard.replay_events_from_jsonl = MagicMock(
        side_effect=lambda *a, **k: order.append("replay") or 0
    )
    dashboard.replay_synthetic_from_context = MagicMock(
        side_effect=lambda *a, **k: order.append("synthetic") or 1
    )
    monkeypatch.setattr("conductor.web.server.WebDashboard", MagicMock(return_value=dashboard))

    from conductor.engine import event_log as event_log_mod

    real_subscriber_cls = event_log_mod.EventLogSubscriber

    def subscriber_factory(*args: Any, **kwargs: Any) -> Any:
        instance = real_subscriber_cls(*args, **kwargs)
        real_on_event = instance.on_event

        def spy_on_event(event: WorkflowEvent) -> None:
            order.append(f"direct:{event.type}")
            return real_on_event(event)

        instance.on_event = spy_on_event
        return instance

    monkeypatch.setattr(event_log_mod, "EventLogSubscriber", subscriber_factory)

    from conductor.cli.run import resume_workflow_async

    with (
        patch("conductor.cli.run.ProviderRegistry") as mock_registry_cls,
        patch("conductor.cli.run.WorkflowEngine") as mock_engine_cls,
        patch("conductor.cli.run._write_terminal_record_for_current_process"),
    ):
        _mock_registry_and_engine(mock_registry_cls, mock_engine_cls, "resume", engine=engine)
        await resume_workflow_async(
            checkpoint_path=cp_path,
            environment="demo",
            guidance=["keep going"],
            web=True,
            web_bg=True,
        )

    assert order[0] == "set_redactor"
    for sink in ("guidance", "prepend", "direct:workflow_started", "replay", "synthetic"):
        assert sink in order, f"missing sink observation: {sink}"
        assert order.index("set_redactor") < order.index(sink)

    # The engine received the CLI-owned pair, and CLI cleanup ran.
    kwargs = mock_engine_cls.call_args.kwargs
    assert isinstance(kwargs["secret_cache"], SecretValueCache)
    assert isinstance(kwargs["redactor"], RunRedactor)
    assert not kwargs["redactor"].active
    assert redaction.current() is None


@pytest.mark.asyncio
async def test_run_without_declared_secrets_is_byte_identical(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Requirement: a workflow with no declared secrets keeps the pre-secrets
    # behavior exactly — the inputs panel is printed verbatim (identity
    # passthrough) and the redactor never activates.
    wf_path = _write_workflow(tmp_path, _PLAIN_WORKFLOW)

    printed: list[str] = []

    from conductor.cli import run as run_module

    real_section = run_module.verbose_log_section

    def spy_section(title: str, content: str) -> None:
        printed.append(content)
        return real_section(title, content)

    monkeypatch.setattr(run_module, "verbose_log_section", spy_section)

    from conductor.cli.run import run_workflow_async

    with (
        patch("conductor.cli.run.ProviderRegistry") as mock_registry_cls,
        patch("conductor.cli.run.WorkflowEngine") as mock_engine_cls,
    ):
        _mock_registry_and_engine(mock_registry_cls, mock_engine_cls, "run")
        result = await run_workflow_async(wf_path, {"key": "plain-value"}, environment=None)

    assert result == {"result": "ok"}
    inputs_panel = json.dumps({"key": "plain-value"}, indent=2, ensure_ascii=False)
    assert printed == [inputs_panel]
    assert REDACTED_MARKER not in printed[0]
    assert redaction.current() is None


@pytest.mark.asyncio
async def test_build_mcp_servers_secrets_defaults_to_legacy() -> None:
    # Requirement: ``secrets`` is optional — omitting it (or passing None)
    # keeps the legacy server translation byte-identical.
    config = WorkflowConfig(
        workflow=WorkflowDef(
            name="mcp-default",
            entry_point="mark",
            runtime=RuntimeConfig(
                provider="copilot",
                mcp_servers={"srv": MCPServerDef(command="srv-command")},
            ),
        ),
        agents=[SetStepDef(name="mark", value="'ok'", routes=[RouteDef(to="$end")])],
    )

    legacy = await _build_mcp_servers(config)
    with_none = await _build_mcp_servers(config, secrets=None)

    assert legacy is not None
    assert legacy == with_none
