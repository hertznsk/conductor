"""Secrets wiring: session lifecycle, resolver views, and engine integration.

Covers the ownership contract of the run-scoped secret pair (self-owned vs
injected), the per-config ``SecretUseIndex`` isolation between root and child
resolver views, the engine's prepare-time reset/refresh and redactor
activation, and the delivery backstops (env-name collision, MCP connect
error redaction for binding-backed servers).
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from conductor import redaction
from conductor.config.environment import (
    EnvironmentDocument,
    ProfileDefinition,
    ResolvedEnvironment,
    SecretBinding,
    SecretBindingSource,
    builtin_local_environment,
)
from conductor.config.schema import (
    ContextConfig,
    LimitsConfig,
    MCPServerDef,
    RouteDef,
    RuntimeConfig,
    ScriptStepDef,
    SecretDelivery,
    StepExecutionConfig,
    StepSecretRef,
    WorkflowConfig,
    WorkflowDef,
    WorkflowStepDef,
)
from conductor.engine.execution_resolution import ExecutionResolver, ExecutionResolverSession
from conductor.engine.secrets import SecretValueCache, index_config
from conductor.engine.workflow import WorkflowEngine
from conductor.events import WorkflowEventEmitter
from conductor.exceptions import ConfigurationError
from conductor.execution import (
    CommandResult,
    CommandSpec,
    RunnerCapabilities,
    RunOutcome,
    RunSpec,
    WorkspaceLease,
)
from conductor.redaction import RunRedactor

_TOKEN_VAR = "CONDUCTOR_TEST_TASK7W_TOKEN"


class RecordingBackend:
    """Batch-capable backend capturing every CommandSpec it receives."""

    def __init__(self) -> None:
        self.prepare_calls: list[RunSpec] = []
        self.run_calls: list[tuple[CommandSpec, WorkspaceLease | None]] = []
        self.finalize_calls: list[tuple[WorkspaceLease, RunOutcome]] = []
        self.lease = WorkspaceLease("lease", "local", "one")

    def capabilities(self) -> RunnerCapabilities:
        return RunnerCapabilities(
            batch=True,
            sessions=False,
            shared_workspace=True,
            snapshots=False,
        )

    async def prepare_run(self, run: RunSpec) -> WorkspaceLease:
        self.prepare_calls.append(run)
        return self.lease

    async def run_command(
        self,
        spec: CommandSpec,
        lease: WorkspaceLease | None,
        *,
        diagnostics: Any = None,
    ) -> CommandResult:
        del diagnostics
        self.run_calls.append((spec, lease))
        return CommandResult(
            outcome="completed",
            stdout=f"{spec.command}\n",
            stderr="",
            exit_code=0,
            resolved_command=spec.command,
            duration_seconds=0.0,
        )

    async def finalize_run(self, lease: WorkspaceLease, outcome: RunOutcome) -> None:
        self.finalize_calls.append((lease, outcome))


def _environment() -> ResolvedEnvironment:
    """An authored environment with one env-sourced ``token`` binding."""
    document = EnvironmentDocument(
        default="default",
        profiles={"default": ProfileDefinition(backend="local")},
        secrets={"token": SecretBinding(source=SecretBindingSource(env=_TOKEN_VAR))},
    )
    return ResolvedEnvironment(
        document=document, name="test", source="path", path=None, digest="sha256:test"
    )


def _script_config(
    *,
    step_name: str = "run",
    delivery_env: str = "DELIVERED_TOKEN",
    env: dict[str, str] | None = None,
    with_secret: bool = True,
) -> WorkflowConfig:
    """A single script step, optionally declaring an env-delivered secret."""
    execution = (
        StepExecutionConfig(
            secrets=[
                StepSecretRef(
                    ref="token",
                    scope="script",
                    delivery=SecretDelivery(env=delivery_env),
                )
            ]
        )
        if with_secret
        else None
    )
    return WorkflowConfig(
        workflow=WorkflowDef(
            name="wiring",
            entry_point=step_name,
            runtime=RuntimeConfig(provider="copilot"),
            context=ContextConfig(mode="accumulate"),
            limits=LimitsConfig(max_iterations=10),
        ),
        agents=[
            ScriptStepDef(
                name=step_name,
                command=f"{step_name}-command",
                env=env or {},
                execution=execution,
                routes=[RouteDef(to="$end")],
            )
        ],
        output={"result": f"{{{{ {step_name}.output.stdout }}}}"},
    )


def _engine(
    config: WorkflowConfig,
    session: ExecutionResolverSession,
    *,
    emitter: WorkflowEventEmitter | None = None,
) -> WorkflowEngine:
    return WorkflowEngine(config, MagicMock(), _execution_session=session, event_emitter=emitter)


# ---------------------------------------------------------------------------
# Session ownership lifecycle
# ---------------------------------------------------------------------------


def test_session_self_creates_secret_primitives_lazily() -> None:
    # Requirement: direct engine construction needs no CLI — the session
    # lazily creates the cache/redactor pair on first access, stably.
    session = ExecutionResolverSession(builtin_local_environment(), RecordingBackend())
    assert session.owns_secrets is True

    cache = session.secret_cache
    redactor = session.redactor
    assert session.secret_cache is cache
    assert session.redactor is redactor
    assert not redactor.active

    # The same lazy pair backs a resolver built over the session.
    config = _script_config(with_secret=False)
    engine = _engine(config, session)
    assert engine._execution_resolver.secret_env_for_step("run") == {}


@pytest.mark.asyncio
async def test_injected_pair_survives_finalize_and_reset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Requirement: an injected (CLI-owned) pair is never cleared by the
    # session — finalize_leases leaves it, and reset_secrets is a no-op.
    monkeypatch.setenv(_TOKEN_VAR, "injected-value-01")
    redactor = RunRedactor()
    cache = SecretValueCache(_environment(), redactor)
    session = ExecutionResolverSession(
        _environment(), RecordingBackend(), secret_cache=cache, redactor=redactor
    )
    assert session.owns_secrets is False

    cache.resolve("token", consumer_class="script", consumer_label="step 'run'")
    assert redactor.active

    session.reset_secrets()
    assert redactor.active
    assert cache.secret_for("token").value == "injected-value-01"

    await session.prepare_leases(RunSpec(run_id="run", workflow_name="wf"))
    await session.finalize_leases("succeeded")
    assert redactor.active
    assert cache.secret_for("token").value == "injected-value-01"


# ---------------------------------------------------------------------------
# Resolver views: per-config index over the shared cache
# ---------------------------------------------------------------------------


def test_resolver_views_are_independent_per_config(monkeypatch: pytest.MonkeyPatch) -> None:
    # Requirement: every resolver view builds its own SecretUseIndex over the
    # shared cache — root and child views never share delivery maps.
    monkeypatch.setenv(_TOKEN_VAR, "shared-value-0001")
    session = ExecutionResolverSession(_environment(), RecordingBackend())
    root_config = _script_config(step_name="run", delivery_env="DELIVERED_TOKEN")
    child_config = _script_config(step_name="inner", delivery_env="CHILD_TOKEN")

    root = ExecutionResolver(root_config, session, workflow_path=None, publish_manifest=False)
    child = ExecutionResolver(child_config, session, workflow_path=None, publish_manifest=False)

    assert root.secret_env_for_step("run") == {"DELIVERED_TOKEN": "shared-value-0001"}
    assert root.secret_env_for_step("inner") == {}
    assert child.secret_env_for_step("inner") == {"CHILD_TOKEN": "shared-value-0001"}
    assert child.secret_env_for_step("run") == {}
    # Both views resolved through the one shared cache (one cached entry).
    assert session.secret_cache.secret_for("token").value == "shared-value-0001"


def test_refresh_secret_uses_rebuilds_after_rotation(monkeypatch: pytest.MonkeyPatch) -> None:
    # Requirement: refresh_secret_uses re-resolves against the cache — after a
    # self-owned reset, a rotated source variable serves the new value.
    monkeypatch.setenv(_TOKEN_VAR, "gen-one-value-1")
    session = ExecutionResolverSession(_environment(), RecordingBackend())
    resolver = ExecutionResolver(
        _script_config(), session, workflow_path=None, publish_manifest=False
    )
    assert resolver.secret_env_for_step("run") == {"DELIVERED_TOKEN": "gen-one-value-1"}

    monkeypatch.setenv(_TOKEN_VAR, "gen-two-value-22")
    session.reset_secrets()
    resolver.refresh_secret_uses()

    assert resolver.secret_env_for_step("run") == {"DELIVERED_TOKEN": "gen-two-value-22"}


def test_resolver_exposes_manifest_inherit_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    # Requirement: inherit_env_for_step reads the compiled manifest profile,
    # defaulting to the local backend's effective True.
    monkeypatch.setenv(_TOKEN_VAR, "s3cr3t-value-0014")
    session = ExecutionResolverSession(_environment(), RecordingBackend())
    resolver = ExecutionResolver(
        _script_config(), session, workflow_path=None, publish_manifest=False
    )
    assert resolver.inherit_env_for_step("run") is True


# ---------------------------------------------------------------------------
# Engine integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_engine_attaches_redactor_to_emitter_idempotently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Requirement: run() attaches the session redactor to the emitter on every
    # generation; repeated attachment of the same redactor is a no-op.
    monkeypatch.setenv(_TOKEN_VAR, "s3cr3t-value-0010")
    session = ExecutionResolverSession(_environment(), RecordingBackend())
    emitter = WorkflowEventEmitter()
    spy = MagicMock(wraps=emitter.set_redactor)
    monkeypatch.setattr(emitter, "set_redactor", spy)
    engine = _engine(_script_config(), session, emitter=emitter)

    await engine.run({})
    await engine.run({})

    assert spy.call_count == 2
    assert all(call.args[0] is session.redactor for call in spy.call_args_list)


@pytest.mark.asyncio
async def test_engine_restores_outer_redaction_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Requirement: token discipline — an outer contextvar redactor survives an
    # inner engine run intact (nested-context regression guard).
    monkeypatch.setenv(_TOKEN_VAR, "s3cr3t-value-0011")
    outer = RunRedactor()
    outer.register(["outer-secret-value"])
    token = redaction.set_current(outer)
    try:
        session = ExecutionResolverSession(_environment(), RecordingBackend())
        engine = _engine(_script_config(), session)
        await engine.run({})

        assert redaction.current() is outer
        assert outer.scrub("outer-secret-value") == "***redacted***"
        # The inner self-owned redactor was still cleaned up at finalize.
        assert not session.redactor.active
    finally:
        redaction.reset_current(token)


@pytest.mark.asyncio
async def test_engine_never_resets_injected_cli_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Requirement: with an injected pair the engine neither resets nor clears
    # it — a value the CLI resolved once is served for the whole run and the
    # redactor survives finalize (the CLI's own cleanup runs later).
    monkeypatch.setenv(_TOKEN_VAR, "prepared-value-01")
    backend = RecordingBackend()
    redactor = RunRedactor()
    cache = SecretValueCache(_environment(), redactor)
    session = ExecutionResolverSession(
        _environment(), backend, secret_cache=cache, redactor=redactor
    )
    # The CLI preflight resolves the declared uses once, up front.
    index_config(_script_config(), cache)
    # The CLI never re-resolves mid-process: a later rotation is invisible.
    monkeypatch.setenv(_TOKEN_VAR, "rotated-value-002")

    engine = _engine(_script_config(), session)
    await engine.run({})

    assert backend.run_calls[-1][0].env["DELIVERED_TOKEN"] == "prepared-value-01"
    assert redactor.active
    assert cache.secret_for("token").value == "prepared-value-01"


@pytest.mark.asyncio
async def test_env_name_collision_between_env_and_secret_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Requirement: a variable declared both in the step's ``env`` and via a
    # secret delivery is a ConfigurationError naming the step and the names.
    monkeypatch.setenv(_TOKEN_VAR, "s3cr3t-value-0012")
    session = ExecutionResolverSession(_environment(), RecordingBackend())
    engine = _engine(_script_config(env={"DELIVERED_TOKEN": "authored"}), session)

    with pytest.raises(ConfigurationError, match="both 'env' and secret delivery"):
        await engine.run({})


@pytest.mark.asyncio
async def test_mcp_step_connect_redacts_errors_for_binding_backed_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Requirement: the Conductor-managed MCP-step connect path forces
    # redact_errors=True for a server carrying declared secret bindings, so
    # connection-failure logging never embeds server-supplied values.
    monkeypatch.setenv(_TOKEN_VAR, "s3cr3t-value-0013")
    config = WorkflowConfig(
        workflow=WorkflowDef(
            name="mcp-redact",
            entry_point="run",
            runtime=RuntimeConfig(
                provider="copilot",
                mcp_servers={
                    "srv": MCPServerDef(
                        command="srv-command",
                        secrets=[
                            StepSecretRef(
                                ref="token",
                                scope="mcp",
                                delivery=SecretDelivery(env="SRV_TOKEN"),
                            )
                        ],
                    )
                },
            ),
            context=ContextConfig(mode="accumulate"),
            limits=LimitsConfig(max_iterations=10),
        ),
        agents=[ScriptStepDef(name="run", command="run-command", routes=[RouteDef(to="$end")])],
    )
    session = ExecutionResolverSession(_environment(), RecordingBackend())
    engine = _engine(config, session)
    assert engine._execution_resolver.deliveries_for_server("srv")

    fake_manager = MagicMock()
    fake_manager.connect_server = AsyncMock()
    monkeypatch.setattr("conductor.mcp.manager.MCPManager", MagicMock(return_value=fake_manager))

    async def _passthrough(name: str, cfg: dict[str, Any]) -> dict[str, Any]:
        return cfg

    monkeypatch.setattr(
        "conductor.engine.workflow.resolve_mcp_server_config",
        _passthrough,
    )

    manager = await engine._get_mcp_step_manager("srv", "/tmp")

    assert manager is fake_manager
    connect_kwargs = fake_manager.connect_server.call_args.kwargs
    assert connect_kwargs["redact_errors"] is True


@pytest.mark.asyncio
async def test_subworkflow_child_resolves_its_own_secrets_lazily(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Requirement: a child workflow's declared secrets resolve lazily at reach
    # time, through the child's own resolver view over the shared run cache —
    # the root config declares nothing and its index stays empty.
    monkeypatch.setenv(_TOKEN_VAR, "child-secret-value")
    child = tmp_path / "child.yaml"
    child.write_text(
        textwrap.dedent(
            """\
            workflow:
              name: child
              entry_point: inner
            agents:
              - name: inner
                type: script
                command: inner-command
                execution:
                  secrets:
                    - ref: token
                      scope: script
                      delivery:
                        env: CHILD_TOKEN
                routes:
                  - to: $end
            output:
              result: "{{ inner.output.stdout }}"
            """
        ),
        encoding="utf-8",
    )
    parent_path = tmp_path / "parent.yaml"
    parent_path.write_text("parent", encoding="utf-8")
    parent_config = WorkflowConfig(
        workflow=WorkflowDef(
            name="parent",
            entry_point="outer",
            runtime=RuntimeConfig(provider="copilot"),
            context=ContextConfig(mode="accumulate"),
            limits=LimitsConfig(max_iterations=10),
        ),
        agents=[
            ScriptStepDef(name="outer", command="outer-command", routes=[RouteDef(to="child")]),
            WorkflowStepDef(name="child", workflow="child.yaml", routes=[RouteDef(to="$end")]),
        ],
        output={"result": "{{ child.output.result }}"},
    )
    backend = RecordingBackend()
    session = ExecutionResolverSession(_environment(), backend)
    engine = WorkflowEngine(
        parent_config,
        MagicMock(),
        workflow_path=parent_path,
        _execution_session=session,
    )
    # The root view never indexed the child's use-site.
    assert engine._execution_resolver.secret_env_for_step("inner") == {}

    result = await engine.run({})

    assert result == {"result": "inner-command\n"}
    commands = [spec.command for spec, _ in backend.run_calls]
    assert commands == ["outer-command", "inner-command"]
    child_spec = backend.run_calls[1][0]
    assert child_spec.env["CHILD_TOKEN"] == "child-secret-value"
    # The root view is untouched by the child's lazy resolution.
    assert engine._execution_resolver.secret_env_for_step("inner") == {}
    assert engine._execution_resolver.secret_env_for_step("outer") == {}
