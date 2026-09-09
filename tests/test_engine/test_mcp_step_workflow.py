"""Integration tests for `type: mcp` steps in WorkflowEngine.

Covers:
- A workflow of ONLY mcp steps completes without the LLM provider ever
  being called
- The result envelope round-trips through ``context.to_dict()`` JSON
  serialization (checkpoint parity)
- set -> mcp -> route on ``output.is_error`` works for both outcomes
- ``mcp_started`` / ``mcp_completed`` / ``mcp_failed`` events carry no
  argument or result values
- An ``output:`` schema mismatch fails the workflow via a single redacted
  ``mcp_failed``
- An unknown server fails at runtime naming the available servers (the
  static validator is never called by ``conductor run``)
- A templated runtime ``working_dir`` rendering to a nonexistent directory
  fails redacted (the rendered path and template stay in the debug log only)
- A value-bearing ``BaseException`` (e.g. ``SystemExit``) from the manager
  wraps into the generic redacted failure; ``CancelledError`` re-raises
  untouched with no ``mcp_failed``
- With ``workflow.context.mode: explicit``, mcp ``arguments`` can reference
  ``workflow.input.*`` (always available to local-render step types) and
  prior-step outputs declared via ``input:``

All MCP interaction is mocked — no real MCP servers are spawned. The mock
pattern mirrors ``tests/test_engine/test_mcp_step_pool.py``: ``MCPManager``
is patched where the engine lazily imports it, and the real
``McpStepExecutor`` runs against the mock manager.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from conductor.config.schema import (
    AgentDef,
    ContextConfig,
    LimitsConfig,
    MCPServerDef,
    OutputField,
    RouteDef,
    RuntimeConfig,
    WorkflowConfig,
    WorkflowDef,
)
from conductor.engine.context import WorkflowContext
from conductor.engine.workflow import WorkflowEngine
from conductor.events import WorkflowEvent, WorkflowEventEmitter
from conductor.exceptions import ExecutionError

_SECRET_ARG = "s3cr3t-token-value"
_SECRET_RESULT = "classified-result-body"


def _make_engine(config: WorkflowConfig) -> WorkflowEngine:
    return WorkflowEngine(config, MagicMock())


def _collect_events(engine: WorkflowEngine) -> list[WorkflowEvent]:
    emitter = WorkflowEventEmitter()
    received: list[WorkflowEvent] = []
    emitter.subscribe(received.append)
    engine._event_emitter = emitter
    return received


def _envelope(is_error: bool = False) -> dict[str, Any]:
    """A raw manager-shaped envelope (before the executor's structured merge)."""
    return {
        "content": [
            {
                "type": "text",
                "text": _SECRET_RESULT,
                "truncated": False,
            }
        ],
        "structured": {"answer": 42},
        "is_error": is_error,
    }


def _patch_manager(envelope: Any = None) -> Any:
    """Patch MCPManager where the engine lazily imports it.

    The fake manager advertises one tool ``echo``. ``envelope`` is either a
    dict returned from every ``call_tool_structured`` or a callable used as
    the AsyncMock side_effect (for failure paths).
    """
    patcher = patch("conductor.mcp.manager.MCPManager")
    manager_cls = patcher.start()
    manager = manager_cls.return_value
    manager.connect_server = AsyncMock(return_value=[])
    manager.get_server_tools = MagicMock(
        return_value=[{"name": "srv__echo", "original_name": "echo"}]
    )
    if callable(envelope):
        manager.call_tool_structured = AsyncMock(side_effect=envelope)
    else:
        manager.call_tool_structured = AsyncMock(return_value=envelope or _envelope())
    return patcher


def _mcp_workflow(*, arguments: dict[str, Any] | None = None) -> WorkflowConfig:
    return WorkflowConfig(
        workflow=WorkflowDef(
            name="mcp-only",
            entry_point="call",
            runtime=RuntimeConfig(
                provider="copilot",
                mcp_servers={"srv": MCPServerDef(type="stdio", command="npx")},
            ),
            context=ContextConfig(mode="accumulate"),
            limits=LimitsConfig(max_iterations=10),
        ),
        agents=[
            AgentDef(
                name="call",
                type="mcp",
                server="srv",
                tool="echo",
                arguments=arguments or {"q": "hello"},
                routes=[RouteDef(to="$end")],
            ),
        ],
        output={"answer": "{{ call.output.answer }}"},
    )


class TestMcpOnlyWorkflow:
    @pytest.mark.asyncio
    async def test_mcp_only_workflow_completes_without_llm(self) -> None:
        # Requirement: a workflow of ONLY mcp steps completes end-to-end and
        # never touches the LLM provider — mcp steps are provider-free.
        provider = MagicMock()
        config = WorkflowConfig(
            workflow=WorkflowDef(
                name="mcp-chain",
                entry_point="first",
                runtime=RuntimeConfig(
                    provider="copilot",
                    mcp_servers={"srv": MCPServerDef(type="stdio", command="npx")},
                ),
                context=ContextConfig(mode="accumulate"),
                limits=LimitsConfig(max_iterations=10),
            ),
            agents=[
                AgentDef(
                    name="first",
                    type="mcp",
                    server="srv",
                    tool="echo",
                    arguments={"q": "hello"},
                    routes=[RouteDef(to="second")],
                ),
                AgentDef(
                    name="second",
                    type="mcp",
                    server="srv",
                    tool="echo",
                    arguments={"q": "follow-up-{{ first.output.answer }}"},
                    routes=[RouteDef(to="$end")],
                ),
            ],
            output={"answer": "{{ second.output.answer }}"},
        )
        patcher = _patch_manager()
        try:
            engine = WorkflowEngine(config, provider)
            result = await engine.run({})
        finally:
            patcher.stop()

        assert result == {"answer": 42}
        provider.execute.assert_not_called()
        # Both steps executed and the second saw the first's merged key.
        assert engine.context.agent_outputs["first"]["answer"] == 42
        assert engine.context.agent_outputs["second"]["answer"] == 42

    @pytest.mark.asyncio
    async def test_context_round_trips_through_json(self) -> None:
        # Requirement: the stored mcp envelope is JSON-safe — a checkpoint
        # save/load (context.to_dict -> json.dumps -> from_dict) preserves it.
        config = _mcp_workflow()
        patcher = _patch_manager()
        try:
            engine = _make_engine(config)
            await engine.run({})
        finally:
            patcher.stop()

        snapshot = engine.context.to_dict()
        rendered = json.dumps(snapshot)
        restored = WorkflowContext.from_dict(json.loads(rendered))
        stored = restored.agent_outputs["call"]
        assert stored["is_error"] is False
        assert stored["answer"] == 42  # merged structured key survives
        assert stored["content"][0]["text"] == _SECRET_RESULT


class TestMcpRouting:
    @pytest.mark.asyncio
    async def test_route_on_is_error_branches_both_ways(self) -> None:
        # Requirement: set -> mcp -> route on output.is_error completes and
        # picks the right branch for both is_error=true and is_error=false.
        config = WorkflowConfig(
            workflow=WorkflowDef(
                name="mcp-route",
                entry_point="flag",
                runtime=RuntimeConfig(
                    provider="copilot",
                    mcp_servers={"srv": MCPServerDef(type="stdio", command="npx")},
                ),
                context=ContextConfig(mode="accumulate"),
                limits=LimitsConfig(max_iterations=10),
            ),
            agents=[
                AgentDef(
                    name="flag",
                    type="set",
                    values={"q": "{{ workflow.input.q }}"},
                    routes=[RouteDef(to="call")],
                ),
                AgentDef(
                    name="call",
                    type="mcp",
                    server="srv",
                    tool="echo",
                    arguments={"q": "{{ flag.output.q }}"},
                    routes=[
                        RouteDef(to="on_error", when="{{ output.is_error }}"),
                        RouteDef(to="on_ok"),
                    ],
                ),
                AgentDef(
                    name="on_error",
                    type="set",
                    value="error-path",
                    routes=[RouteDef(to="$end")],
                ),
                AgentDef(
                    name="on_ok",
                    type="set",
                    value="ok-path",
                    routes=[RouteDef(to="$end")],
                ),
            ],
            output={
                "path": (
                    "{% if on_error is defined %}{{ on_error.output }}"
                    "{% else %}{{ on_ok.output }}{% endif %}"
                )
            },
        )

        patcher = _patch_manager(_envelope(is_error=False))
        try:
            result_ok = await _make_engine(config).run({"q": "hi"})
        finally:
            patcher.stop()

        patcher = _patch_manager(_envelope(is_error=True))
        try:
            result_err = await _make_engine(config).run({"q": "hi"})
        finally:
            patcher.stop()

        assert result_ok == {"path": "ok-path"}
        assert result_err == {"path": "error-path"}


class TestMcpEventPayloads:
    @pytest.mark.asyncio
    async def test_events_carry_no_argument_or_result_values(self) -> None:
        # Requirement: no mcp_* event payload may contain argument values or
        # result values — only server/tool/argument_keys/elapsed/is_error/
        # result_bytes/truncated/spill_path (failed: error_type/message).
        config = _mcp_workflow(arguments={"token": _SECRET_ARG, "q": "hello"})
        engine = _make_engine(config)
        received = _collect_events(engine)

        patcher = _patch_manager()
        try:
            await engine.run({})
        finally:
            patcher.stop()

        mcp_events = [ev for ev in received if ev.type.startswith("mcp_")]
        assert {ev.type for ev in mcp_events} == {"mcp_started", "mcp_completed"}

        started = next(ev for ev in mcp_events if ev.type == "mcp_started")
        # Argument VALUES stay out; only key names are listed.
        assert started.data["argument_keys"] == ["q", "token"]
        assert _SECRET_ARG not in json.dumps(started.data)

        completed = next(ev for ev in mcp_events if ev.type == "mcp_completed")
        assert completed.data["server"] == "srv"
        assert completed.data["tool"] == "echo"
        assert completed.data["is_error"] is False
        assert completed.data["truncated"] is False
        assert completed.data["result_bytes"] > 0
        # The result body never appears in ANY event payload.
        assert _SECRET_RESULT not in json.dumps([ev.data for ev in received])

    @pytest.mark.asyncio
    async def test_failure_event_is_redacted(self) -> None:
        # Requirement: a failing mcp step emits exactly one mcp_failed whose
        # message is generic (no raw exception text), raises a redacted
        # ExecutionError (not the raw manager error — its text can carry
        # argument/result values), and workflow_failed carries no canary
        # value either.
        def _boom(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            raise RuntimeError(f"call exploded with {_SECRET_ARG}")

        config = _mcp_workflow()
        engine = _make_engine(config)
        received = _collect_events(engine)

        patcher = _patch_manager(_boom)
        try:
            with pytest.raises(ExecutionError) as exc_info:
                await engine.run({})
        finally:
            patcher.stop()

        # The raised error is the generic redacted form, not the manager's
        # raw text (which embedded the secret argument value).
        assert "call exploded" not in str(exc_info.value)
        assert _SECRET_ARG not in str(exc_info.value)
        assert "see debug logs" in str(exc_info.value)

        failed = [ev for ev in received if ev.type == "mcp_failed"]
        assert len(failed) == 1
        failed_data = failed[0].data
        assert failed_data["error_type"] == "RuntimeError"
        assert _SECRET_ARG not in json.dumps(failed_data)
        assert _SECRET_RESULT not in json.dumps(failed_data)
        # The manager saw the call; the failure came from inside the step.
        assert failed_data["server"] == "srv"
        assert failed_data["tool"] == "echo"
        # workflow_failed must not smuggle the raw exception text either.
        wf_failed = [ev for ev in received if ev.type == "workflow_failed"]
        assert len(wf_failed) == 1
        assert _SECRET_ARG not in json.dumps(wf_failed[0].data)
        assert "call exploded" not in json.dumps(wf_failed[0].data)


class TestMcpOutputSchemaValidation:
    @pytest.mark.asyncio
    async def test_schema_mismatch_fails_workflow_with_single_redacted_event(self) -> None:
        # Requirement: an output: schema mismatch on an mcp step raises a
        # REDACTED ExecutionError (not the ValidationError, whose message
        # echoes the received result value) and emits exactly one redacted
        # mcp_failed — the canary result scalar must appear in neither the
        # raised error nor any event payload (incl. workflow_failed).
        canary = "SECRET_CANARY_9f13"
        config = _mcp_workflow()
        config.agents[0].output = {"answer": OutputField(type="number")}

        def _value_envelope(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            return {
                "content": [{"type": "text", "text": "ok", "truncated": False}],
                "structured": {"answer": canary},
                "is_error": False,
            }

        engine = _make_engine(config)
        received = _collect_events(engine)

        patcher = _patch_manager(_value_envelope)
        try:
            with pytest.raises(ExecutionError) as exc_info:
                await engine.run({})
        finally:
            patcher.stop()

        # The raised error is the generic redacted form — the schema
        # ValidationError's "received: '<value>'" text must not surface.
        assert canary not in str(exc_info.value)
        assert "see debug logs" in str(exc_info.value)

        failed = [ev for ev in received if ev.type == "mcp_failed"]
        assert len(failed) == 1
        assert failed[0].data["error_type"] == "ValidationError"
        assert canary not in json.dumps(failed[0].data)
        # No mcp_completed on the failure path; the run itself failed too.
        assert not any(ev.type == "mcp_completed" for ev in received)
        wf_failed = [ev for ev in received if ev.type == "workflow_failed"]
        assert len(wf_failed) == 1
        assert canary not in json.dumps(wf_failed[0].data)


class TestMcpRuntimeChecks:
    @pytest.mark.asyncio
    async def test_unknown_server_names_available_servers(self) -> None:
        # Requirement: an mcp step referencing a server absent from
        # runtime.mcp_servers raises ExecutionError naming the available
        # servers at runtime (conductor run never calls the validator).
        config = WorkflowConfig(
            workflow=WorkflowDef(
                name="mcp-ghost",
                entry_point="call",
                runtime=RuntimeConfig(
                    provider="copilot",
                    mcp_servers={"srv": MCPServerDef(type="stdio", command="npx")},
                ),
                context=ContextConfig(mode="accumulate"),
                limits=LimitsConfig(max_iterations=10),
            ),
            agents=[
                AgentDef(
                    name="call",
                    type="mcp",
                    server="ghost",
                    tool="echo",
                    routes=[RouteDef(to="$end")],
                ),
            ],
            output={},
        )
        engine = _make_engine(config)
        received = _collect_events(engine)

        with pytest.raises(ExecutionError, match="Available servers: srv"):
            await engine.run({})

        assert any(ev.type == "mcp_failed" for ev in received)

    @pytest.mark.asyncio
    async def test_templated_working_dir_value_leaks_no_values(self) -> None:
        # Requirement: the runtime working_dir not-a-directory check must not
        # leak the Jinja-rendered path or the raw template — both are rendered
        # from the execution context and can carry values. The propagated
        # message is redacted; the authored name-only runtime-check messages
        # (like the unknown-server one above) stay verbatim.
        canary = "SECRET_CANARY_9f13"
        config = WorkflowConfig(
            workflow=WorkflowDef(
                name="mcp-cwd-leak",
                entry_point="call",
                runtime=RuntimeConfig(
                    provider="copilot",
                    working_dir="{{ workflow.input.secret_path }}",
                    mcp_servers={"srv": MCPServerDef(type="stdio", command="npx")},
                ),
                context=ContextConfig(mode="accumulate"),
                limits=LimitsConfig(max_iterations=10),
            ),
            agents=[
                AgentDef(
                    name="call",
                    type="mcp",
                    server="srv",
                    tool="echo",
                    routes=[RouteDef(to="$end")],
                ),
            ],
            output={},
        )
        engine = _make_engine(config)
        received = _collect_events(engine)

        with pytest.raises(ExecutionError) as excinfo:
            await engine.run({"secret_path": f"/nonexistent/{canary}"})

        assert "does not exist or is not a directory" in str(excinfo.value)
        assert canary not in str(excinfo.value)
        assert "{{ workflow.input.secret_path }}" not in str(excinfo.value)

        failed = [ev for ev in received if ev.type == "mcp_failed"]
        assert len(failed) == 1
        assert canary not in json.dumps(failed[0].data)
        assert "{{ workflow.input.secret_path }}" not in json.dumps(failed[0].data)
        wf_failed = [ev for ev in received if ev.type == "workflow_failed"]
        assert len(wf_failed) == 1
        assert canary not in json.dumps(wf_failed[0].data)
        assert "{{ workflow.input.secret_path }}" not in json.dumps(wf_failed[0].data)


class TestMcpBaseExceptionRedaction:
    @pytest.mark.asyncio
    async def test_system_exit_from_manager_wraps_redacted(self) -> None:
        # Requirement: a value-bearing BaseException raised from MCP
        # SDK / connect / renderer code (e.g. SystemExit("secret")) must not
        # bypass the redaction and reach workflow_failed via the outer
        # except BaseException — it becomes a redacted step failure with
        # exactly one mcp_failed, and the canary appears in no surface.
        canary = "SECRET_CANARY_9f13"
        engine = _make_engine(_mcp_workflow())
        received = _collect_events(engine)

        async def _raise_system_exit(*_args: Any, **_kwargs: Any) -> Any:
            raise SystemExit(canary)

        patcher = _patch_manager(envelope=_raise_system_exit)
        try:
            with pytest.raises(ExecutionError) as exc_info:
                await engine.run({})
        finally:
            patcher.stop()

        assert "SystemExit" not in str(exc_info.value)
        assert canary not in str(exc_info.value)
        failed = [ev for ev in received if ev.type == "mcp_failed"]
        assert len(failed) == 1
        assert canary not in json.dumps(failed[0].data)
        wf_failed = [ev for ev in received if ev.type == "workflow_failed"]
        assert len(wf_failed) == 1
        assert canary not in json.dumps(wf_failed[0].data)

    @pytest.mark.asyncio
    async def test_cancelled_step_reraises_without_mcp_failed(self) -> None:
        # Requirement: cancellation is not a step failure — the step re-raises
        # CancelledError untouched and emits NO mcp_failed, preserving the
        # engine's cancellation semantics.
        engine = _make_engine(_mcp_workflow())
        received = _collect_events(engine)

        async def _raise_cancelled(*_args: Any, **_kwargs: Any) -> Any:
            raise asyncio.CancelledError()

        patcher = _patch_manager(envelope=_raise_cancelled)
        try:
            with pytest.raises(asyncio.CancelledError):
                await engine._run_mcp_step(
                    engine.config.agents[0], engine.context.build_for_agent("call", [])
                )
        finally:
            patcher.stop()

        assert not any(ev.type == "mcp_failed" for ev in received)


class TestMcpExplicitContextMode:
    @pytest.mark.asyncio
    async def test_arguments_render_workflow_inputs_and_declared_outputs(self) -> None:
        # Requirement: with workflow.context.mode: explicit, the validator
        # allows workflow.input.* references in mcp arguments (mirroring
        # set/script/wait), so the runtime context must make them renderable
        # too — a reference that passes static validation must render at
        # run time. Prior-step outputs still require an explicit input:
        # declaration, as for every step type.
        config = WorkflowConfig(
            workflow=WorkflowDef(
                name="mcp-explicit",
                entry_point="prep",
                runtime=RuntimeConfig(
                    provider="copilot",
                    mcp_servers={"srv": MCPServerDef(type="stdio", command="npx")},
                ),
                context=ContextConfig(mode="explicit"),
                limits=LimitsConfig(max_iterations=10),
            ),
            agents=[
                AgentDef(
                    name="prep",
                    type="set",
                    value="from-prep",
                    routes=[RouteDef(to="call")],
                ),
                AgentDef(
                    name="call",
                    type="mcp",
                    server="srv",
                    tool="echo",
                    input=["prep.output"],
                    arguments={
                        "q": "{{ workflow.input.question }}",
                        "prior": "{{ prep.output }}",
                    },
                    routes=[RouteDef(to="$end")],
                ),
            ],
            output={},
        )
        engine = _make_engine(config)

        captured: list[dict[str, Any]] = []

        async def capture_call(_server: str, _tool: str, arguments: dict[str, Any]) -> Any:
            captured.append(arguments)
            return _envelope()

        patcher = _patch_manager(envelope=capture_call)
        try:
            await engine.run({"question": "what is python?"})
        finally:
            patcher.stop()

        assert captured == [{"q": "what is python?", "prior": "from-prep"}]
