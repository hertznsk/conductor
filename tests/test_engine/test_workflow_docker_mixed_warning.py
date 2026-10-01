"""Runtime warning contract for mixed local and Docker script execution."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from conductor.config.environment import (
    DockerProfileOptions,
    EnvironmentDocument,
    ProfileDefinition,
    ResolvedEnvironment,
)
from conductor.config.schema import (
    RouteDef,
    ScriptStepDef,
    StepExecutionConfig,
    WorkflowConfig,
    WorkflowDef,
)
from conductor.engine.execution_resolution import BACKEND_FACTORIES
from conductor.engine.run_manifest import BACKEND_CAPABILITY_PROVIDERS
from conductor.engine.workflow import WorkflowEngine
from conductor.execution.types import (
    CommandResult,
    CommandSpec,
    RunnerCapabilities,
    RunOutcome,
    RunSpec,
    WorkspaceLease,
)


class _DockerBackend:
    """Stateless docker-backend stub: no daemon contact, completes instantly."""

    def capabilities(self) -> RunnerCapabilities:
        return RunnerCapabilities(
            batch=True,
            sessions=False,
            shared_workspace=True,
            snapshots=False,
        )

    async def prepare_run(self, run: RunSpec) -> WorkspaceLease:
        return WorkspaceLease(lease_id=run.run_id, backend="docker", incarnation="test")

    async def run_command(
        self,
        spec: CommandSpec,
        lease: WorkspaceLease | None,
        *,
        diagnostics=None,
    ) -> CommandResult:
        return CommandResult(outcome="completed", exit_code=0, resolved_command=spec.command)

    async def finalize_run(self, lease: WorkspaceLease, outcome: RunOutcome) -> None:
        return None


def _script(name: str, profile: str, route: str) -> ScriptStepDef:
    return ScriptStepDef(
        name=name,
        command="true",
        timeout=None,
        execution=StepExecutionConfig(profile=profile),
        routes=[RouteDef(to=route)],
    )


@pytest.mark.asyncio
async def test_root_run_logs_mixed_backend_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Requirement: a root run warns exactly once when its script steps span
    # local and docker backends, before any step executes.
    workflow_path = tmp_path / "workflow.yaml"
    workflow_path.write_text("workflow: mixed\n", encoding="utf-8")
    environment = ResolvedEnvironment(
        document=EnvironmentDocument(
            profiles={
                "local": ProfileDefinition(backend="local"),
                "container": ProfileDefinition(
                    backend="docker",
                    docker=DockerProfileOptions(image="busybox@sha256:" + "a" * 64),
                ),
            }
        ),
        name="test",
        source="path",
        path=None,
        digest="sha256:test",
    )
    config = WorkflowConfig(
        workflow=WorkflowDef(name="mixed", entry_point="host"),
        agents=[
            _script("host", "local", "box"),
            _script("box", "container", "$end"),
        ],
    )
    backend = _DockerBackend()
    monkeypatch.setitem(BACKEND_CAPABILITY_PROVIDERS, "docker", backend)
    monkeypatch.setitem(BACKEND_FACTORIES, "docker", lambda: backend)

    async def fake_prepare(*args, **kwargs):
        return None

    monkeypatch.setattr("conductor.engine.workflow.prepare_run_bundle", fake_prepare)
    caplog.set_level(logging.WARNING, logger="conductor.engine.workflow")

    engine = WorkflowEngine(
        config,
        workflow_path=workflow_path,
        execution_environment=environment,
    )
    await engine.run({})

    messages = [record.getMessage() for record in caplog.records]
    assert messages.count("Workflow uses mixed script execution backends: docker, local") == 1
