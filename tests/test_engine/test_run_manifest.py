"""Tests for ``conductor.engine.run_manifest`` — the resolved run manifest compiler.

Covers (per the execution-profiles plan, Todo 3):

* Oracle O1 — a profile-less workflow compiles against the built-in
  environment with every executable step on ``default`` / ``local``.
* Oracle O3 — inline for-each agents key as ``for_each.<group>.agent`` and two
  same-named inline agents in different groups get distinct keys.
* Oracle O5 — every manifest model is frozen and forbids extra fields.
* The precedence chain: step-level > workflow defaults > environment default,
  with a full-chain error on a complete miss.
* Unknown-profile errors list the available profiles.
* Script steps require a backend with the ``batch`` capability.
* Workflow digest spelling (``sha256:<hex>``) and ``None`` for path-less
  configs; byte-identical output across two compilations (determinism).
"""

from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path
from typing import Any, Literal

import pytest
from pydantic import ValidationError

from conductor.config.environment import (
    EnvironmentDocument,
    ProfileDefinition,
    ResolvedEnvironment,
    builtin_local_environment,
)
from conductor.config.schema import (
    AgentDef,
    ForEachDef,
    OutputField,
    RouteDef,
    ScriptStepDef,
    SetStepDef,
    StepExecutionConfig,
    WorkflowConfig,
    WorkflowDef,
    WorkflowDefaults,
)
from conductor.engine import run_manifest
from conductor.engine.run_manifest import (
    AuditInfo,
    EnvironmentIdentity,
    ResolvedStepProfile,
    WorkflowIdentity,
    compile_run_manifest,
)
from conductor.exceptions import ConfigurationError
from conductor.execution.types import (
    CommandResult,
    CommandSpec,
    RunnerCapabilities,
    RunOutcome,
    RunSpec,
    WorkspaceLease,
)


def _agent(name: str, routes: list[RouteDef] | None = None, **kwargs: Any) -> AgentDef:
    """Build a minimal executable agent step."""
    return AgentDef(
        name=name,
        model="gpt-4",
        prompt="test",
        output={"value": OutputField(type="string")},
        routes=routes if routes is not None else [RouteDef(to="$end")],
        **kwargs,
    )


def _single_agent_config(name: str = "start", **agent_kwargs: Any) -> WorkflowConfig:
    """Build a one-agent workflow config with the agent as entry point."""
    return WorkflowConfig(
        workflow=WorkflowDef(name="manifest-test", entry_point=name),
        agents=[_agent(name, **agent_kwargs)],
        output={"result": "{{ start.output.value }}"},
    )


def _resolved_environment(
    profiles: dict[str, str],
    *,
    default: str | None = None,
    name: str = "test-env",
    source: Literal["builtin", "path", "project", "user"] = "path",
) -> ResolvedEnvironment:
    """Build a resolved environment from ``{profile: backend}`` shorthand."""
    document = EnvironmentDocument(
        default=default,
        profiles={key: ProfileDefinition(backend=value) for key, value in profiles.items()},
    )
    canonical = json.dumps(document.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return ResolvedEnvironment(
        document=document,
        name=name,
        source=source,
        path=None,
        digest=f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}",
    )


class _NoBatchBackend:
    """Fake backend lacking the batch capability (registry monkeypatch)."""

    def capabilities(self) -> RunnerCapabilities:
        return RunnerCapabilities(
            batch=False,
            sessions=False,
            shared_workspace=False,
            snapshots=False,
        )

    async def prepare_run(self, run: RunSpec) -> WorkspaceLease:
        raise NotImplementedError

    async def run_command(
        self,
        spec: CommandSpec,
        lease: WorkspaceLease | None,
        *,
        diagnostics=None,
    ) -> CommandResult:
        raise NotImplementedError

    async def finalize_run(self, lease: WorkspaceLease, outcome: RunOutcome) -> None:
        raise NotImplementedError


def test_profile_less_workflow_compiles_against_builtin() -> None:
    # Requirement (Oracle O1): a workflow with no execution configuration at
    # all must compile against the built-in environment, with every executable
    # step resolved to the built-in "default" profile on the "local" backend.
    config = WorkflowConfig(
        workflow=WorkflowDef(name="plain", entry_point="start"),
        agents=[
            _agent("start", routes=[RouteDef(to="run")]),
            ScriptStepDef(name="run", command="echo", routes=[RouteDef(to="$end")]),
        ],
        output={"result": "{{ run.output.stdout }}"},
    )

    manifest = compile_run_manifest(
        config, workflow_path=None, environment=builtin_local_environment()
    )

    assert manifest.profiles == {
        "start": ResolvedStepProfile(profile="default", backend="local"),
        "run": ResolvedStepProfile(profile="default", backend="local"),
    }
    assert manifest.environment.name == "local/default"
    assert manifest.environment.source == "builtin"


def test_inline_for_each_identity_keys() -> None:
    # Requirement (Oracle O3): two inline for-each agents with the SAME step
    # name in different groups get distinct for_each.<group>.agent keys, and a
    # top-level step keys by its bare name.
    config = WorkflowConfig(
        workflow=WorkflowDef(name="foreach-keys", entry_point="start"),
        agents=[_agent("start")],
        for_each=[
            ForEachDef(
                name="first",
                type="for_each",
                source="workflow.input.items",
                **{"as": "item"},
                agent=AgentDef(name="worker", model="gpt-4", prompt="a"),
            ),
            ForEachDef(
                name="second",
                type="for_each",
                source="workflow.input.items",
                **{"as": "item"},
                agent=AgentDef(name="worker", model="gpt-4", prompt="b"),
            ),
        ],
        output={"result": "{{ start.output.value }}"},
    )

    manifest = compile_run_manifest(
        config, workflow_path=None, environment=builtin_local_environment()
    )

    assert set(manifest.profiles) == {"start", "for_each.first.agent", "for_each.second.agent"}
    assert manifest.profiles["for_each.first.agent"] == manifest.profiles["for_each.second.agent"]


def test_manifest_is_frozen() -> None:
    # Requirement (Oracle O5): manifest models are frozen — attribute
    # assignment raises a validation error.
    manifest = compile_run_manifest(
        _single_agent_config(), workflow_path=None, environment=builtin_local_environment()
    )

    with pytest.raises(ValidationError):
        manifest.conductor_version = "tampered"

    step_profile = ResolvedStepProfile(profile="default", backend="local")
    with pytest.raises(ValidationError):
        step_profile.backend = "other"

    with pytest.raises(ValidationError):
        WorkflowIdentity.model_validate({"name": "x", "digest": None, "extra": "nope"})


class TestPrecedence:
    """Requirement: profile resolution follows step > workflow defaults > environment default."""

    def _config(self, *, step_profile: str | None, workflow_profile: str | None) -> WorkflowConfig:
        agent_kwargs: dict[str, Any] = {}
        if step_profile is not None:
            agent_kwargs["execution"] = StepExecutionConfig(profile=step_profile)
        workflow_kwargs: dict[str, Any] = {}
        if workflow_profile is not None:
            workflow_kwargs["defaults"] = WorkflowDefaults(
                execution=StepExecutionConfig(profile=workflow_profile)
            )
        return WorkflowConfig(
            workflow=WorkflowDef(name="precedence", entry_point="start", **workflow_kwargs),
            agents=[_agent("start", **agent_kwargs)],
            output={"result": "{{ start.output.value }}"},
        )

    def test_step_level_profile_wins(self) -> None:
        # Requirement: an explicit step-level profile beats both the workflow
        # default and the environment default.
        environment = _resolved_environment({"shell": "local", "batch": "local"}, default="batch")
        manifest = compile_run_manifest(
            self._config(step_profile="shell", workflow_profile="batch"),
            workflow_path=None,
            environment=environment,
        )
        assert manifest.profiles["start"] == ResolvedStepProfile(profile="shell", backend="local")

    def test_workflow_default_applies_without_step_profile(self) -> None:
        # Requirement: with no step-level profile, the workflow default wins
        # over the environment default.
        environment = _resolved_environment({"shell": "local", "batch": "local"}, default="batch")
        manifest = compile_run_manifest(
            self._config(step_profile=None, workflow_profile="shell"),
            workflow_path=None,
            environment=environment,
        )
        assert manifest.profiles["start"] == ResolvedStepProfile(profile="shell", backend="local")

    def test_environment_default_applies_without_any_config_profile(self) -> None:
        # Requirement: with neither step nor workflow profile, the environment
        # document's default applies.
        environment = _resolved_environment({"shell": "local"}, default="shell")
        manifest = compile_run_manifest(
            self._config(step_profile=None, workflow_profile=None),
            workflow_path=None,
            environment=environment,
        )
        assert manifest.profiles["start"] == ResolvedStepProfile(profile="shell", backend="local")

    def test_all_miss_error_names_the_full_chain(self) -> None:
        # Requirement: a complete miss names the step and every precedence
        # level, so the author sees the whole chain that failed.
        environment = _resolved_environment({"shell": "local"}, default=None)
        with pytest.raises(ConfigurationError) as exc_info:
            compile_run_manifest(
                self._config(step_profile=None, workflow_profile=None),
                workflow_path=None,
                environment=environment,
            )
        message = str(exc_info.value)
        assert "start" in message
        assert "execution.profile" in message
        assert "workflow.defaults.execution.profile" in message
        assert "default" in message


def test_unknown_profile_lists_available() -> None:
    # Requirement: naming a profile the environment does not define fails with
    # a ConfigurationError that lists the available profiles.
    config = _single_agent_config(execution=StepExecutionConfig(profile="nope"))
    environment = _resolved_environment({"shell": "local", "batch": "local"}, default="shell")

    with pytest.raises(ConfigurationError) as exc_info:
        compile_run_manifest(config, workflow_path=None, environment=environment)

    message = str(exc_info.value)
    assert "nope" in message
    assert "batch" in message and "shell" in message


def test_script_step_requires_batch_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    # Requirement: a script step resolving to a backend without the batch
    # capability is a compile-time ConfigurationError, even when the profile
    # name itself resolves.
    monkeypatch.setattr(
        run_manifest,
        "BACKEND_CAPABILITY_PROVIDERS",
        {"local": _NoBatchBackend()},
    )
    config = WorkflowConfig(
        workflow=WorkflowDef(name="script", entry_point="run"),
        agents=[ScriptStepDef(name="run", command="echo", routes=[RouteDef(to="$end")])],
        output={"result": "{{ run.output.stdout }}"},
    )

    with pytest.raises(ConfigurationError) as exc_info:
        compile_run_manifest(config, workflow_path=None, environment=builtin_local_environment())

    message = str(exc_info.value)
    assert "run" in message
    assert "batch" in message


def test_pathless_workflow_digest_is_none() -> None:
    # Requirement: a config built without a workflow file (programmatic
    # construction) compiles with workflow.digest=None — there is nothing to
    # hash.
    manifest = compile_run_manifest(
        _single_agent_config(), workflow_path=None, environment=builtin_local_environment()
    )
    assert manifest.workflow.digest is None


def test_workflow_digest_is_sha256_of_file_bytes(tmp_path: Path) -> None:
    # Requirement: with a workflow file, the digest is sha256 over the raw
    # file bytes, spelled "sha256:<hex>".
    workflow_path = tmp_path / "wf.yaml"
    content = b"name: digest-check\n"
    workflow_path.write_bytes(content)

    config = _single_agent_config()
    manifest = compile_run_manifest(
        config, workflow_path=workflow_path, environment=builtin_local_environment()
    )

    assert manifest.workflow.digest == f"sha256:{hashlib.sha256(content).hexdigest()}"


def test_engine_local_steps_are_not_in_manifest() -> None:
    # Requirement: engine-local steps (set, wait, terminate, human_gate,
    # questions) never run on a backend and are excluded from the manifest.
    config = WorkflowConfig(
        workflow=WorkflowDef(name="local-steps", entry_point="setup"),
        agents=[
            SetStepDef(name="setup", value="'ok'", routes=[RouteDef(to="run")]),
            ScriptStepDef(name="run", command="echo", routes=[RouteDef(to="$end")]),
        ],
        output={"result": "{{ run.output.stdout }}"},
    )

    manifest = compile_run_manifest(
        config, workflow_path=None, environment=builtin_local_environment()
    )

    assert set(manifest.profiles) == {"run"}


def test_environment_identity_pins_name_source_and_digest() -> None:
    # Requirement: the environment identity pins name, source, and the
    # document digest computed at resolution time — reused verbatim, not
    # recomputed here.
    environment = _resolved_environment(
        {"shell": "local"}, default="shell", name="prod", source="project"
    )

    manifest = compile_run_manifest(
        _single_agent_config(), workflow_path=None, environment=environment
    )

    assert manifest.environment == EnvironmentIdentity(
        name="prod", source="project", digest=environment.digest
    )


def test_audit_info_classifies_non_hermetic_compatibility() -> None:
    # Requirement: the manifest self-classifies as non-hermetic compatibility
    # — resolution depends on machine-local environment documents.
    manifest = compile_run_manifest(
        _single_agent_config(), workflow_path=None, environment=builtin_local_environment()
    )

    assert manifest.audit == AuditInfo(hermetic=False, classification="non-hermetic-compatibility")
    assert manifest.version == 1


def test_compile_is_deterministic(tmp_path: Path) -> None:
    # Requirement: two compilations of the same inputs produce byte-identical
    # model_dump(mode="json") — the manifest is run-invariant.
    workflow_path = tmp_path / "wf.yaml"
    workflow_path.write_bytes(b"name: deterministic\n")
    config = _single_agent_config()
    environment = _resolved_environment({"shell": "local"}, default="shell")

    first = compile_run_manifest(config, workflow_path=workflow_path, environment=environment)
    second = compile_run_manifest(config, workflow_path=workflow_path, environment=environment)

    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_manifest_has_no_run_varying_fields() -> None:
    # Requirement: the manifest carries no run id, timestamps, inputs, CLI
    # overrides, or absolute paths — only run-invariant identity fields.
    manifest = compile_run_manifest(
        _single_agent_config(), workflow_path=None, environment=builtin_local_environment()
    )

    dumped = manifest.model_dump(mode="json")
    assert set(dumped) == {
        "version",
        "workflow",
        "environment",
        "profiles",
        "conductor_version",
        "audit",
    }
    assert set(dumped["workflow"]) == {"name", "digest"}
    assert set(dumped["environment"]) == {"name", "source", "digest"}


def test_module_is_reachable_via_engine_package() -> None:
    # Requirement: Todo 4's resolver consumes compile_run_manifest through
    # conductor.engine.run_manifest — the submodule is importable from the
    # engine package.
    module = importlib.import_module("conductor.engine.run_manifest")
    assert module.compile_run_manifest is compile_run_manifest


def test_capability_registry_seeds_local_with_batch() -> None:
    # Requirement: the capability registry seeds "local" with a backend that
    # declares batch — the assumption script steps rely on at compile time.
    backend = run_manifest.BACKEND_CAPABILITY_PROVIDERS["local"]
    assert backend.capabilities().batch is True
