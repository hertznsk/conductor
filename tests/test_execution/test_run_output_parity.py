"""Pinned provider-free run output and event-surface parity."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

from conductor.config.schema import (
    ContextConfig,
    LimitsConfig,
    RouteDef,
    RuntimeConfig,
    ScriptStepDef,
    SetStepDef,
    WorkflowConfig,
    WorkflowDef,
)
from conductor.engine.workflow import WorkflowEngine
from conductor.events import WorkflowEvent, WorkflowEventEmitter


@pytest.mark.asyncio
async def test_provider_free_workflow_output_shape_pinned() -> None:
    # Requirement: execution profiles add only system.execution_manifest to the run surface.
    config = WorkflowConfig(
        workflow=WorkflowDef(
            name="provider-free-parity",
            entry_point="mark",
            runtime=RuntimeConfig(provider="copilot"),
            context=ContextConfig(mode="accumulate"),
            limits=LimitsConfig(max_iterations=10),
        ),
        agents=[
            SetStepDef(
                name="mark",
                value="'hello'",
                routes=[RouteDef(to="say")],
            ),
            ScriptStepDef(
                name="say",
                command=sys.executable,
                args=["-c", "print('{{ mark.output }}')"],
                routes=[RouteDef(to="check42")],
            ),
            ScriptStepDef(
                name="check42",
                command=sys.executable,
                args=["-c", "import sys; sys.exit(42)"],
                routes=[RouteDef(to="$end", when="exit_code == 42")],
            ),
        ],
        output={
            "greeting": "{{ mark.output }}",
            "said": "{{ say.output.stdout }}",
            "code": "{{ check42.output.exit_code }}",
        },
    )
    events: list[WorkflowEvent] = []
    emitter = WorkflowEventEmitter()
    emitter.subscribe(events.append)

    result = await WorkflowEngine(config, MagicMock(), event_emitter=emitter).run({})

    assert result == {"greeting": "hello", "said": "hello\n", "code": 42}
    assert [event.type for event in events] == [
        "workflow_started",
        "agent_started",
        "set_started",
        "set_completed",
        "route_taken",
        "agent_started",
        "script_started",
        "script_completed",
        "route_taken",
        "agent_started",
        "script_started",
        "script_completed",
        "route_taken",
        "workflow_completed",
    ]

    started = events[0].data
    system = started["system"]
    assert set(system) == {
        "pid",
        "platform",
        "python_version",
        "conductor_version",
        "cwd",
        "started_at",
        "run_id",
        "log_file",
        "bg_mode",
        "execution_manifest",
    }
    assert {
        "dashboard_port",
        "dashboard_url",
        "parent_pid",
        "bg_stderr_log",
        "bg_stdout_log",
    }.isdisjoint(system)

    manifest = system["execution_manifest"]
    assert manifest["version"] == 1
    assert manifest["environment"]["name"] == "local/default"
    assert manifest["environment"]["source"] == "builtin"
    assert manifest["environment"]["digest"].startswith("sha256:")
    assert manifest["workflow"]["name"] == "provider-free-parity"
    assert manifest["audit"] == {
        "hermetic": False,
        "classification": "non-hermetic-compatibility",
    }
    assert manifest["profiles"] == {
        "say": {"profile": "default", "backend": "local"},
        "check42": {"profile": "default", "backend": "local"},
    }
