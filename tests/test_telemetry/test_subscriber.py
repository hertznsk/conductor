"""Requirements tests for event-driven OpenTelemetry span creation."""

from __future__ import annotations

import logging
from collections.abc import Generator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol
from unittest.mock import Mock

import pytest

from conductor.events import WorkflowEvent
from conductor.telemetry import guards
from conductor.telemetry.semconv import (
    CONDUCTOR_MCP_RESULT_BYTES,
    CONDUCTOR_MCP_SERVER,
    CONDUCTOR_MCP_TRUNCATED,
    CONDUCTOR_RESUMED,
    CONDUCTOR_STEP_TYPE,
    ERROR_TYPE,
    GEN_AI_AGENT_NAME,
    GEN_AI_CONVERSATION_ID,
    GEN_AI_OPERATION_NAME,
    GEN_AI_TOOL_NAME,
    GEN_AI_USAGE_INPUT_TOKENS,
    GEN_AI_USAGE_OUTPUT_TOKENS,
    INVOKE_AGENT,
    INVOKE_WORKFLOW,
)
from conductor.telemetry.subscriber import TelemetrySubscriber

if TYPE_CHECKING:
    from opentelemetry.sdk.trace import ReadableSpan, TracerProvider


class SpanExporter(Protocol):
    """Provide finished spans for assertions without importing the optional SDK."""

    def get_finished_spans(self) -> tuple[ReadableSpan, ...]:
        """Return every span received by the in-memory exporter."""
        ...


@dataclass(frozen=True, slots=True)
class Tracing:
    """Own an enabled subscriber and its synchronous test exporter."""

    subscriber: TelemetrySubscriber
    exporter: SpanExporter
    provider: TracerProvider


@pytest.fixture
def tracing() -> Generator[Tracing]:
    """Provide an in-memory exporter with a detached-span subscriber."""
    pytest.importorskip("opentelemetry.sdk")
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    provider = TracerProvider()
    exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    subscriber = TelemetrySubscriber(provider)
    yield Tracing(subscriber=subscriber, exporter=exporter, provider=provider)
    subscriber.close()


def _event(event_type: str, timestamp: float, **data: object) -> WorkflowEvent:
    """Build one synthetic engine event at a deterministic timestamp."""
    return WorkflowEvent(type=event_type, timestamp=timestamp, data=data)


def _spans(exporter: SpanExporter) -> list[ReadableSpan]:
    """Return exported spans without coupling tests to an internal fixture type."""
    return list(exporter.get_finished_spans())


def _span(spans: list[ReadableSpan], name: str) -> ReadableSpan:
    """Return the uniquely named exported span."""
    return next(span for span in spans if span.name == name)


def test_subscriber_creates_nested_workflow_agent_and_tool_spans(
    tracing: Tracing,
) -> None:
    """Requirement: paired events form a detached root → agent → tool span tree."""
    # Given: an enabled tracer and a complete LLM agent lifecycle.
    subscriber = tracing.subscriber

    # When: the engine event sequence reaches successful workflow completion.
    subscriber.on_event(_event("workflow_started", 10.0, name="research", run_id="run-1"))
    subscriber.on_event(
        _event("agent_started", 11.0, agent_name="planner", iteration=1, agent_type="agent")
    )
    subscriber.on_event(
        _event(
            "agent_tool_start",
            12.0,
            agent_name="planner",
            tool_name="search",
            tool_call_id="c1",
        )
    )
    subscriber.on_event(
        _event(
            "agent_tool_complete", 13.0, agent_name="planner", tool_name="search", tool_call_id="c1"
        )
    )
    subscriber.on_event(
        _event(
            "agent_completed",
            14.0,
            agent_name="planner",
            model="gpt-5",
            input_tokens=12,
            output_tokens=8,
            cost_usd=0.02,
        )
    )
    subscriber.on_event(_event("workflow_completed", 15.0))

    # Then: names, attributes, and explicit parent identities are preserved.
    spans = _spans(tracing.exporter)
    root = _span(spans, f"{INVOKE_WORKFLOW} research")
    agent = _span(spans, f"{INVOKE_AGENT} planner")
    tool = _span(spans, "execute_tool search")
    agent_parent = agent.parent
    tool_parent = tool.parent
    root_context = root.context
    agent_context = agent.context
    assert agent_parent is not None
    assert tool_parent is not None
    assert root_context is not None
    assert agent_context is not None
    assert root.attributes is not None
    assert agent.attributes is not None
    assert tool.attributes is not None
    assert agent_parent.span_id == root_context.span_id
    assert tool_parent.span_id == agent_context.span_id
    assert root.attributes[GEN_AI_OPERATION_NAME] == INVOKE_WORKFLOW
    assert root.attributes[GEN_AI_CONVERSATION_ID] == "run-1"
    assert agent.attributes[GEN_AI_AGENT_NAME] == "planner"
    assert agent.attributes[GEN_AI_USAGE_INPUT_TOKENS] == 12
    assert agent.attributes[GEN_AI_USAGE_OUTPUT_TOKENS] == 8
    assert tool.attributes[GEN_AI_TOOL_NAME] == "search"
    assert subscriber._open_spans == {}


def test_workflow_failure_closes_an_unpaired_agent_as_error(
    tracing: Tracing,
) -> None:
    """Requirement: workflow_failed closes LLM work that has no agent_failed event."""
    # Given: an agent whose provider fails before its completion event.
    subscriber = tracing.subscriber
    subscriber.on_event(_event("workflow_started", 10.0, name="failure", run_id="run-2"))
    subscriber.on_event(_event("agent_started", 11.0, agent_name="writer", iteration=1))

    # When: the engine reports only the terminal workflow failure.
    subscriber.on_event(
        _event(
            "workflow_failed",
            12.0,
            agent_name="writer",
            error_type="ProviderError",
            message="provider disconnected",
        )
    )

    # Then: both the root and pending agent end with an error status.
    from opentelemetry.trace import StatusCode

    agent = _span(_spans(tracing.exporter), f"{INVOKE_AGENT} writer")
    assert agent.attributes is not None
    assert agent.status.status_code is StatusCode.ERROR
    assert agent.attributes[ERROR_TYPE] == "ProviderError"
    assert agent.attributes["error.message"] == "provider disconnected"
    assert subscriber._open_spans == {}


def test_duplicate_workflow_start_for_same_run_reuses_the_root_span(
    tracing: Tracing,
) -> None:
    """Requirement: a resume duplicate does not create a second root trace."""
    # Given: a run whose resume path emits workflow_started a second time.
    subscriber = tracing.subscriber
    subscriber.on_event(_event("workflow_started", 10.0, name="resume", run_id="run-3"))

    # When: the duplicate uses the same run identifier.
    subscriber.on_event(_event("workflow_started", 11.0, name="resume", run_id="run-3"))
    subscriber.on_event(_event("workflow_completed", 12.0))

    # Then: exactly one root was exported and marks the continuation.
    spans = _spans(tracing.exporter)
    roots = [span for span in spans if span.name == f"{INVOKE_WORKFLOW} resume"]
    assert len(roots) == 1
    assert roots[0].attributes is not None
    assert roots[0].attributes[CONDUCTOR_RESUMED] is True


def test_gate_events_create_short_correlated_spans(
    tracing: Tracing,
) -> None:
    """Requirement: human-gate events never hold a span across user waiting time."""
    # Given: an open human-gate step.
    subscriber = tracing.subscriber
    subscriber.on_event(_event("workflow_started", 10.0, name="approval", run_id="run-4"))
    subscriber.on_event(
        _event("agent_started", 11.0, agent_name="approve", iteration=1, agent_type="human_gate")
    )

    # When: the gate is presented and resolved at distinct event times.
    subscriber.on_event(_event("gate_presented", 12.0, agent_name="approve"))
    subscriber.on_event(_event("gate_resolved", 20.0, agent_name="approve"))
    subscriber.on_event(_event("workflow_completed", 21.0))

    # Then: each gate event is represented by a zero-duration correlated span.
    gate_spans = [
        span
        for span in _spans(tracing.exporter)
        if span.attributes
        and span.attributes.get("conductor.gate.event") in {"gate_presented", "gate_resolved"}
    ]
    assert len(gate_spans) == 2
    assert {span.start_time == span.end_time for span in gate_spans} == {True}
    attributes = [span.attributes for span in gate_spans]
    assert all(attributes)
    assert {attribute[GEN_AI_CONVERSATION_ID] for attribute in attributes if attribute} == {"run-4"}
    step_types = {attribute[CONDUCTOR_STEP_TYPE] for attribute in attributes if attribute}
    assert step_types == {"human_gate"}


def test_close_ends_open_spans_and_resets_telemetry_context(
    tracing: Tracing,
) -> None:
    """Requirement: final cleanup ends unfinished spans and drops process-local state."""
    # Given: a tracer context and spans still open at CLI teardown.
    subscriber = tracing.subscriber
    guards.set_current_tracer_provider(tracing.provider)
    guards.set_current_run_id("run-5")
    subscriber.on_event(_event("workflow_started", 10.0, name="teardown", run_id="run-5"))
    subscriber.on_event(_event("agent_started", 11.0, agent_name="open", iteration=1))

    # When: the CLI's finally block closes the subscriber.
    subscriber.close()

    # Then: all spans have the default status and no latched run state remains.
    from opentelemetry.trace import StatusCode

    assert {span.status.status_code for span in _spans(tracing.exporter)} == {StatusCode.UNSET}
    assert subscriber._open_spans == {}
    assert guards.current_tracer_provider() is None
    assert guards.current_run_id() is None


def test_event_timestamps_are_converted_from_seconds_to_nanoseconds(
    tracing: Tracing,
) -> None:
    """Requirement: detached spans use event timestamps instead of subscriber wall time."""
    # Given: synthetic timestamps far from the test process's wall clock.
    subscriber = tracing.subscriber

    # When: an agent lifecycle is emitted with Unix-second values.
    subscriber.on_event(_event("workflow_started", 10_000.25, name="time", run_id="run-6"))
    subscriber.on_event(_event("agent_started", 10_001.5, agent_name="clock", iteration=1))
    subscriber.on_event(_event("agent_completed", 10_003.75, agent_name="clock"))
    subscriber.on_event(_event("workflow_completed", 10_004.0))

    # Then: OpenTelemetry receives integer nanoseconds derived from those values.
    agent = _span(_spans(tracing.exporter), f"{INVOKE_AGENT} clock")
    assert agent.start_time == 10_001_500_000_000
    assert agent.end_time == 10_003_750_000_000


def test_repeated_unnamed_tool_calls_close_in_fifo_order(
    tracing: Tracing,
) -> None:
    """Requirement: same-named tools without call IDs remain distinct span instances."""
    # Given: two overlapping calls from a provider that omits call identifiers.
    subscriber = tracing.subscriber
    subscriber.on_event(_event("workflow_started", 10.0, name="tools", run_id="run-7"))
    subscriber.on_event(_event("agent_started", 11.0, agent_name="worker", iteration=1))
    subscriber.on_event(_event("agent_tool_start", 12.0, agent_name="worker", tool_name="lookup"))
    subscriber.on_event(_event("agent_tool_start", 13.0, agent_name="worker", tool_name="lookup"))

    # When: matching completions arrive without IDs in their original order.
    subscriber.on_event(
        _event("agent_tool_complete", 14.0, agent_name="worker", tool_name="lookup")
    )
    subscriber.on_event(
        _event("agent_tool_complete", 15.0, agent_name="worker", tool_name="lookup")
    )
    subscriber.on_event(_event("agent_completed", 16.0, agent_name="worker"))
    subscriber.on_event(_event("workflow_completed", 17.0))

    # Then: each call produces a separately ended span rather than overwriting the first.
    tools = [span for span in _spans(tracing.exporter) if span.name == "execute_tool lookup"]
    assert len(tools) == 2
    span_ids = {span.context.span_id for span in tools if span.context is not None}
    assert len(span_ids) == 2


def test_same_tool_call_id_from_parallel_agents_closes_matching_spans(
    tracing: Tracing,
) -> None:
    """Requirement: tool call IDs are isolated by their concurrent agent parent."""
    # Given: two parallel agents whose providers independently emit the same call ID.
    subscriber = tracing.subscriber
    subscriber.on_event(_event("workflow_started", 10.0, name="tools", run_id="run-8"))
    subscriber.on_event(_event("parallel_started", 11.0, group_name="workers"))
    subscriber.on_event(
        _event("parallel_agent_started", 12.0, group_name="workers", agent_name="alpha")
    )
    subscriber.on_event(
        _event("parallel_agent_started", 13.0, group_name="workers", agent_name="beta")
    )
    subscriber.on_event(
        _event(
            "agent_tool_start",
            14.0,
            agent_name="alpha",
            tool_name="lookup",
            tool_call_id="shared-call",
        )
    )
    subscriber.on_event(
        _event(
            "agent_tool_start",
            15.0,
            agent_name="beta",
            tool_name="lookup",
            tool_call_id="shared-call",
        )
    )

    # When: both completions carry the shared call ID in the opposite start order.
    subscriber.on_event(
        _event(
            "agent_tool_complete",
            16.0,
            agent_name="beta",
            tool_name="lookup",
            tool_call_id="shared-call",
        )
    )
    subscriber.on_event(
        _event(
            "agent_tool_complete",
            17.0,
            agent_name="alpha",
            tool_name="lookup",
            tool_call_id="shared-call",
        )
    )
    subscriber.on_event(
        _event("parallel_agent_completed", 18.0, group_name="workers", agent_name="alpha")
    )
    subscriber.on_event(
        _event("parallel_agent_completed", 19.0, group_name="workers", agent_name="beta")
    )
    subscriber.on_event(_event("parallel_completed", 20.0, group_name="workers"))
    subscriber.on_event(_event("workflow_completed", 21.0))

    # Then: each tool span remains parented and ended by its own agent event.
    spans = _spans(tracing.exporter)
    alpha = _span(spans, f"{INVOKE_AGENT} alpha")
    beta = _span(spans, f"{INVOKE_AGENT} beta")
    assert alpha.context is not None
    assert beta.context is not None
    tools_by_parent = {
        span.parent.span_id: span
        for span in spans
        if span.name == "execute_tool lookup" and span.parent is not None
    }
    alpha_tool = tools_by_parent[alpha.context.span_id]
    beta_tool = tools_by_parent[beta.context.span_id]
    assert len(tools_by_parent) == 2
    assert alpha_tool.end_time == 17_000_000_000
    assert beta_tool.end_time == 16_000_000_000


def test_mcp_step_creates_one_tool_span_without_recording_values(
    tracing: Tracing,
) -> None:
    """Requirement: a deterministic MCP step is traced as one value-free tool call."""
    # Given: a sequential MCP step with metadata that must remain outside telemetry.
    subscriber = tracing.subscriber
    subscriber.on_event(_event("workflow_started", 10.0, name="mcp", run_id="run-mcp"))

    # When: the MCP lifecycle completes successfully.
    subscriber.on_event(
        _event(
            "mcp_started",
            11.0,
            agent_name="lookup",
            iteration=2,
            server="catalog",
            tool="search",
            argument_keys=["secret_query"],
        )
    )
    subscriber.on_event(
        _event(
            "mcp_completed",
            12.0,
            agent_name="lookup",
            server="catalog",
            tool="search",
            is_error=False,
            result_bytes=42,
            truncated=True,
            spill_path="/private/result.txt",
        )
    )
    subscriber.on_event(_event("workflow_completed", 13.0))

    # Then: the call is a direct workflow child with safe MCP metadata only.
    spans = _spans(tracing.exporter)
    root = _span(spans, f"{INVOKE_WORKFLOW} mcp")
    tool = _span(spans, "execute_tool search")
    assert root.context is not None
    assert tool.parent is not None
    assert tool.parent.span_id == root.context.span_id
    assert tool.start_time == 11_000_000_000
    assert tool.end_time == 12_000_000_000
    assert tool.attributes is not None
    assert tool.attributes[GEN_AI_OPERATION_NAME] == "execute_tool"
    assert tool.attributes[GEN_AI_AGENT_NAME] == "lookup"
    assert tool.attributes[GEN_AI_TOOL_NAME] == "search"
    assert tool.attributes[CONDUCTOR_STEP_TYPE] == "mcp"
    assert tool.attributes[CONDUCTOR_MCP_SERVER] == "catalog"
    assert tool.attributes[CONDUCTOR_MCP_RESULT_BYTES] == 42
    assert tool.attributes[CONDUCTOR_MCP_TRUNCATED] is True
    assert "argument_keys" not in tool.attributes
    assert "spill_path" not in tool.attributes
    assert all(span.name != f"{INVOKE_AGENT} lookup" for span in spans)


def test_mcp_steps_in_parallel_close_by_member_identity(
    tracing: Tracing,
) -> None:
    """Requirement: overlapping MCP members remain distinct when completion order reverses."""
    # Given: two parallel members calling the same server tool.
    subscriber = tracing.subscriber
    subscriber.on_event(_event("workflow_started", 10.0, name="mcp", run_id="run-parallel"))
    subscriber.on_event(_event("parallel_started", 11.0, group_name="workers"))
    for timestamp, agent in ((12.0, "alpha"), (13.0, "beta")):
        subscriber.on_event(
            _event(
                "mcp_started",
                timestamp,
                agent_name=agent,
                group_name="workers",
                server="catalog",
                tool="search",
            )
        )

    # When: terminal events arrive in reverse order.
    subscriber.on_event(
        _event(
            "mcp_completed",
            14.0,
            agent_name="beta",
            group_name="workers",
            server="catalog",
            tool="search",
            is_error=False,
        )
    )
    subscriber.on_event(
        _event(
            "mcp_completed",
            15.0,
            agent_name="alpha",
            group_name="workers",
            server="catalog",
            tool="search",
            is_error=False,
        )
    )
    subscriber.on_event(_event("parallel_completed", 16.0, group_name="workers"))
    subscriber.on_event(_event("workflow_completed", 17.0))

    # Then: both tool spans are children of the group and preserve their own end time.
    spans = _spans(tracing.exporter)
    group = _span(spans, f"{INVOKE_AGENT} workers")
    assert group.context is not None
    tools = [span for span in spans if span.name == "execute_tool search"]
    assert len(tools) == 2
    by_agent = {
        span.attributes[GEN_AI_AGENT_NAME]: span for span in tools if span.attributes is not None
    }
    assert by_agent["alpha"].end_time == 15_000_000_000
    assert by_agent["beta"].end_time == 14_000_000_000
    assert {span.parent.span_id for span in tools if span.parent is not None} == {
        group.context.span_id
    }


def test_mcp_tool_error_marks_only_the_tool_span_as_error(
    tracing: Tracing,
) -> None:
    """Requirement: a routed MCP error is visible without failing its workflow span."""
    # Given: an MCP server returns a protocol-level error envelope.
    subscriber = tracing.subscriber
    subscriber.on_event(_event("workflow_started", 10.0, name="mcp", run_id="run-error"))
    subscriber.on_event(
        _event(
            "mcp_started",
            11.0,
            agent_name="lookup",
            server="catalog",
            tool="search",
        )
    )

    # When: the result is routable data and the workflow completes successfully.
    subscriber.on_event(
        _event(
            "mcp_completed",
            12.0,
            agent_name="lookup",
            server="catalog",
            tool="search",
            is_error=True,
        )
    )
    subscriber.on_event(_event("workflow_completed", 13.0))

    # Then: only the tool operation reports an error.
    from opentelemetry.trace import StatusCode

    spans = _spans(tracing.exporter)
    root = _span(spans, f"{INVOKE_WORKFLOW} mcp")
    tool = _span(spans, "execute_tool search")
    assert tool.attributes is not None
    assert tool.attributes[ERROR_TYPE] == "MCPToolError"
    assert tool.status.status_code is StatusCode.ERROR
    assert root.status.status_code is StatusCode.UNSET


def test_mcp_failure_closes_the_tool_span_with_redacted_error(
    tracing: Tracing,
) -> None:
    """Requirement: an MCP execution failure records only its safe event message."""
    # Given: an active deterministic MCP call.
    subscriber = tracing.subscriber
    subscriber.on_event(_event("workflow_started", 10.0, name="mcp", run_id="run-failed"))
    subscriber.on_event(
        _event(
            "mcp_started",
            11.0,
            agent_name="lookup",
            server="catalog",
            tool="search",
        )
    )

    # When: the engine emits its redacted MCP and workflow failures.
    subscriber.on_event(
        _event(
            "mcp_failed",
            12.0,
            agent_name="lookup",
            server="catalog",
            tool="search",
            error_type="ExecutionError",
            message="MCP step 'lookup' failed; details: /tmp/diagnostic.log",
        )
    )
    subscriber.on_event(
        _event(
            "workflow_failed",
            13.0,
            error_type="ExecutionError",
            message="MCP step 'lookup' failed; details: /tmp/diagnostic.log",
        )
    )

    # Then: the tool span carries the bounded event error and no span leaks.
    from opentelemetry.trace import StatusCode

    tool = _span(_spans(tracing.exporter), "execute_tool search")
    assert tool.attributes is not None
    assert tool.attributes[ERROR_TYPE] == "ExecutionError"
    assert tool.attributes["error.message"] == (
        "MCP step 'lookup' failed; details: /tmp/diagnostic.log"
    )
    assert tool.status.status_code is StatusCode.ERROR
    assert subscriber._open_spans == {}


def test_agent_pause_does_not_close_an_ordinary_agent_span(
    tracing: Tracing,
) -> None:
    """Requirement: MCP interruption handling cannot alter an ordinary LLM span."""
    # Given: an active provider-backed agent.
    subscriber = tracing.subscriber
    subscriber.on_event(_event("workflow_started", 10.0, name="agent", run_id="run-agent"))
    subscriber.on_event(_event("agent_started", 11.0, agent_name="lookup", iteration=1))

    # When: the dashboard reports a pause with the same agent name.
    subscriber.on_event(_event("agent_paused", 12.0, agent_name="lookup"))

    # Then: the agent remains open until its own terminal lifecycle event.
    assert [key[0] for key in subscriber._open_spans] == [
        f"{INVOKE_WORKFLOW} agent",
        f"{INVOKE_AGENT} lookup",
    ]
    subscriber.on_event(_event("agent_completed", 13.0, agent_name="lookup"))
    subscriber.on_event(_event("workflow_completed", 14.0))
    agent = _span(_spans(tracing.exporter), f"{INVOKE_AGENT} lookup")
    assert agent.end_time == 13_000_000_000


def test_for_each_mcp_steps_use_index_to_select_their_item_parent(
    tracing: Tracing,
) -> None:
    """Requirement: duplicate item keys cannot cross-parent concurrent MCP calls."""
    # Given: two active items with the same display key but distinct indexes.
    subscriber = tracing.subscriber
    subscriber.on_event(_event("workflow_started", 10.0, name="mcp", run_id="run-items"))
    subscriber.on_event(_event("for_each_started", 11.0, group_name="items"))
    subscriber.on_event(
        _event("for_each_item_started", 12.0, group_name="items", item_key="same", index=0)
    )
    subscriber.on_event(
        _event("for_each_item_started", 13.0, group_name="items", item_key="same", index=1)
    )
    for timestamp, index in ((14.0, 0), (15.0, 1)):
        subscriber.on_event(
            _event(
                "mcp_started",
                timestamp,
                agent_name="lookup",
                group_name="items",
                item_key="same",
                index=index,
                server="catalog",
                tool="search",
            )
        )

    # When: both calls and item envelopes complete independently.
    for timestamp, index in ((16.0, 1), (17.0, 0)):
        subscriber.on_event(
            _event(
                "mcp_completed",
                timestamp,
                agent_name="lookup",
                group_name="items",
                item_key="same",
                index=index,
                server="catalog",
                tool="search",
                is_error=False,
            )
        )
        subscriber.on_event(
            _event(
                "for_each_item_completed",
                timestamp + 0.1,
                group_name="items",
                item_key="same",
                index=index,
            )
        )
    subscriber.on_event(_event("for_each_completed", 18.0, group_name="items"))
    subscriber.on_event(_event("workflow_completed", 19.0))

    # Then: each tool span belongs to the item identified by its index.
    spans = _spans(tracing.exporter)
    item_spans = sorted(
        (span for span in spans if span.name == f"{INVOKE_AGENT} items[same]"),
        key=lambda span: span.start_time or 0,
    )
    tools = sorted(
        (span for span in spans if span.name == "execute_tool search"),
        key=lambda span: span.start_time or 0,
    )
    assert len(item_spans) == len(tools) == 2
    assert all(item.context is not None for item in item_spans)
    assert all(tool.parent is not None for tool in tools)
    assert [tool.parent.span_id for tool in tools if tool.parent is not None] == [
        item.context.span_id for item in item_spans if item.context is not None
    ]


def test_pausing_an_mcp_step_closes_the_interrupted_attempt(
    tracing: Tracing,
) -> None:
    """Requirement: resuming an MCP step starts a new span without leaking the first."""
    # Given: an in-flight MCP call that is interrupted by a dashboard pause.
    subscriber = tracing.subscriber
    subscriber.on_event(_event("workflow_started", 10.0, name="mcp", run_id="run-pause"))
    subscriber.on_event(
        _event(
            "mcp_started",
            11.0,
            agent_name="lookup",
            server="catalog",
            tool="search",
        )
    )

    # When: the user pauses, resumes, and the replacement attempt succeeds.
    subscriber.on_event(_event("agent_paused", 12.0, agent_name="lookup"))
    subscriber.on_event(
        _event(
            "mcp_started",
            13.0,
            agent_name="lookup",
            server="catalog",
            tool="search",
        )
    )
    subscriber.on_event(
        _event(
            "mcp_completed",
            14.0,
            agent_name="lookup",
            server="catalog",
            tool="search",
            is_error=False,
        )
    )
    subscriber.on_event(_event("workflow_completed", 15.0))

    # Then: both attempts end at their own lifecycle boundary.
    tools = sorted(
        (span for span in _spans(tracing.exporter) if span.name == "execute_tool search"),
        key=lambda span: span.start_time or 0,
    )
    assert len(tools) == 2
    assert tools[0].end_time == 12_000_000_000
    assert tools[1].end_time == 14_000_000_000
    assert subscriber._open_spans == {}


def test_close_attempts_shutdown_when_force_flush_raises(
    tracing: Tracing,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Requirement: a flush failure cannot skip tracer-provider shutdown."""
    # Given: a tracer provider whose flush fails during non-throwing cleanup.
    force_flush = Mock(side_effect=RuntimeError("flush failed"))
    shutdown = Mock()
    monkeypatch.setattr(tracing.provider, "force_flush", force_flush)
    monkeypatch.setattr(tracing.provider, "shutdown", shutdown)

    # When: the telemetry subscriber closes.
    tracing.subscriber.close()

    # Then: shutdown is attempted and the cleanup error remains suppressed.
    force_flush.assert_called_once_with(timeout_millis=5_000)
    shutdown.assert_called_once_with()


@pytest.mark.parametrize("method", ["start", "join"])
def test_close_contains_thread_failure(
    tracing: Tracing,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    method: str,
) -> None:
    """Requirement: thread lifecycle failure cannot escape telemetry cleanup."""
    # Given: the platform refuses one exporter-drain thread operation.
    monkeypatch.setattr(
        f"conductor.telemetry.subscriber.threading.Thread.{method}",
        Mock(side_effect=RuntimeError("thread unavailable")),
    )
    caplog.set_level(logging.WARNING, logger="conductor.telemetry.subscriber")

    # When: subscriber cleanup runs.
    tracing.subscriber.close()

    # Then: cleanup returns, resets guards, and reports possible trace loss.
    assert guards.is_telemetry_active() is False
    assert "exporter cleanup failed" in caplog.text


def test_child_workflow_failure_does_not_close_the_parent_run(
    tracing: Tracing,
) -> None:
    """Requirement: a child workflow failure leaves its parent hierarchy open."""
    # Given: a parent agent that delegates to one nested workflow.
    subscriber = tracing.subscriber
    subscriber.on_event(_event("workflow_started", 10.0, name="parent", run_id="run-8"))
    subscriber.on_event(_event("agent_started", 11.0, agent_name="delegate", iteration=1))
    subscriber.on_event(
        _event(
            "subworkflow_started",
            12.0,
            agent_name="delegate",
            parent_path=[],
            slot_key="delegate",
        )
    )
    subscriber.on_event(
        _event(
            "workflow_started",
            13.0,
            name="child",
            subworkflow_path=["delegate"],
        )
    )
    subscriber.on_event(
        _event(
            "agent_started",
            14.0,
            agent_name="nested",
            iteration=1,
            subworkflow_path=["delegate"],
        )
    )

    # When: only the nested engine reports a terminal failure.
    subscriber.on_event(
        _event(
            "workflow_failed",
            15.0,
            subworkflow_path=["delegate"],
            error_type="ProviderError",
        )
    )

    # Then: the root and delegating agent remain open for their outer terminal events.
    assert len(subscriber._open_spans) == 2
    subscriber.on_event(
        _event(
            "subworkflow_failed",
            16.0,
            agent_name="delegate",
            parent_path=[],
            slot_key="delegate",
            error_type="ProviderError",
        )
    )
    subscriber.on_event(
        _event("workflow_failed", 17.0, error_type="ProviderError", message="child failed")
    )

    root = _span(_spans(tracing.exporter), f"{INVOKE_WORKFLOW} parent")
    assert root.status.status_code.name == "ERROR"
    assert subscriber._open_spans == {}


def test_overlapping_for_each_validators_close_their_own_spans(
    tracing: Tracing,
) -> None:
    """Requirement: for-each validator spans resolve by item identity, not display name."""
    # Given: two items of one for-each group whose validators overlap in time.
    subscriber = tracing.subscriber
    subscriber.on_event(_event("workflow_started", 10.0, name="parent", run_id="run-9"))
    subscriber.on_event(_event("for_each_started", 11.0, group_name="items"))
    subscriber.on_event(
        _event("for_each_item_started", 12.0, group_name="items", item_key="0", index=0)
    )
    subscriber.on_event(
        _event("for_each_item_started", 13.0, group_name="items", item_key="1", index=1)
    )
    subscriber.on_event(
        _event("agent_validator_start", 14.0, agent_name="items", item_key="0", index=0)
    )
    subscriber.on_event(
        _event("agent_validator_start", 15.0, agent_name="items", item_key="1", index=1)
    )

    # When: item 0's validator completes while item 1's is still running.
    subscriber.on_event(
        _event(
            "agent_validator_complete",
            16.0,
            agent_name="items",
            item_key="0",
            index=0,
            input_tokens=11,
        )
    )

    # Then: item 0's validator span closed with its own metadata; item 1's is open.
    spans = _spans(tracing.exporter)
    validators = [s for s in spans if s.name.endswith("(validator)")]
    assert len(validators) == 1
    assert validators[0].attributes is not None
    assert validators[0].attributes[GEN_AI_USAGE_INPUT_TOKENS] == 11
    open_names = [key[0] for key in subscriber._open_spans]
    assert open_names.count("invoke_agent items (validator)") == 1

    # And: item 1's validator completes independently, keyed by its own index.
    subscriber.on_event(
        _event(
            "agent_validator_complete",
            17.0,
            agent_name="items",
            item_key="1",
            index=1,
            errored=True,
        )
    )
    spans = _spans(tracing.exporter)
    validators = [s for s in spans if s.name.endswith("(validator)")]
    assert len(validators) == 2
    errored = [s for s in validators if s.status.status_code.name == "ERROR"]
    assert len(errored) == 1
    assert errored[0].attributes is not None
    assert GEN_AI_USAGE_INPUT_TOKENS not in errored[0].attributes


def test_for_each_subworkflow_completion_leaves_the_item_span_open(
    tracing: Tracing,
) -> None:
    """Requirement: subworkflow_completed never terminates a for-each item span early."""
    # Given: a sub-workflow running inside a for-each item.
    subscriber = tracing.subscriber
    subscriber.on_event(_event("workflow_started", 10.0, name="parent", run_id="run-10"))
    subscriber.on_event(_event("for_each_started", 11.0, group_name="items"))
    subscriber.on_event(
        _event("for_each_item_started", 12.0, group_name="items", item_key="0", index=0)
    )
    subscriber.on_event(
        _event(
            "subworkflow_started",
            13.0,
            agent_name="items",
            item_key="0",
            iteration=1,
            parent_path=[],
            slot_key="items[0]",
        )
    )
    subscriber.on_event(
        _event("workflow_started", 14.0, name="child", subworkflow_path=["items[0]"])
    )

    # When: the child workflow finishes and the subworkflow envelope completes.
    subscriber.on_event(_event("workflow_completed", 15.0, subworkflow_path=["items[0]"]))
    subscriber.on_event(
        _event(
            "subworkflow_completed",
            16.0,
            agent_name="items",
            item_key="0",
            iteration=1,
            parent_path=[],
            slot_key="items[0]",
        )
    )

    # Then: the item span is still open — its terminal envelope has not fired.
    assert len(subscriber._open_spans) == 3  # root + group + item
    assert _spans(tracing.exporter) != []  # the child workflow span closed
    item_open = [key for key in subscriber._open_spans if key[0] == "invoke_agent items[0]"]
    assert len(item_open) == 1

    # And: the item's own terminal event closes it with its aggregated cost.
    subscriber.on_event(
        _event(
            "for_each_item_completed",
            17.0,
            group_name="items",
            item_key="0",
            index=0,
            cost_usd=0.25,
        )
    )
    item_span = _span(_spans(tracing.exporter), "invoke_agent items[0]")
    assert item_span.attributes is not None
    assert item_span.attributes["conductor.cost_usd"] == 0.25
