"""Build detached OpenTelemetry spans from Conductor workflow events."""

from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING

from opentelemetry import trace

from conductor.events import WorkflowEvent
from conductor.telemetry import guards
from conductor.telemetry import subscriber_execution as execution
from conductor.telemetry import subscriber_workflows as workflows
from conductor.telemetry.subscriber_state import SpanState
from conductor.telemetry.subscriber_types import SpanKey

if TYPE_CHECKING:
    from opentelemetry.sdk.trace import TracerProvider

logger = logging.getLogger(__name__)

# Single overall deadline for draining the exporter at close. The pinned SDK's
# BatchSpanProcessor ignores force_flush's own timeout and drains synchronously
# (one exporter-timeout per queued batch), so the bound has to be enforced
# from outside the exporter — see TelemetrySubscriber.close.
_CLOSE_EXPORT_DEADLINE_SECONDS = 5.0


class TelemetrySubscriber:
    """Translate paired workflow events into explicitly parented detached spans."""

    def __init__(self, tracer_provider: TracerProvider | None, *, resumed: bool = False) -> None:
        """Create an inert subscriber when the optional SDK is unavailable.

        Args:
            tracer_provider: OpenTelemetry SDK tracer provider for this run.
            resumed: Whether this subscriber represents a resumed workflow run.
                When True, the root workflow span is stamped with
                ``conductor.resumed=true``.
        """
        self._tracer_provider = tracer_provider
        self._state = SpanState(tracer_provider, resumed=resumed) if tracer_provider else None
        self._closed = False

    @property
    def _open_spans(self) -> dict[SpanKey, trace.Span]:
        """Expose open spans for compatibility with focused lifecycle tests."""
        return self._state.open_spans if self._state else {}

    def on_event(self, event: WorkflowEvent) -> None:
        """Consume one event without relying on a task-local current span."""
        if self._state is None or self._closed:
            return
        _dispatch(self._state, event)

    def close(
        self,
        *,
        failed: bool = False,
        error_type: str | None = None,
        error_message: str | None = None,
    ) -> None:
        """Finish open spans, drain exporters under a deadline, reset guards.

        Args:
            failed: Terminal outcome of the run for spans still open at close
                — an interrupt, a cancellation, or an exception that escaped
                the engine before it could emit a terminal event. Those spans
                are ended as failed instead of looking like clean completions.
                Spans a genuine ``workflow_completed`` / ``workflow_failed``
                already closed are untouched either way.
            error_type: Classifier stamped on unfinished spans when ``failed``
                (e.g. ``KeyboardInterrupt``).
            error_message: Detail stamped on unfinished spans when ``failed``.

        Never raises: cleanup runs fail-open so it cannot mask an in-flight
        workflow or dashboard exception, and the process-local guards are
        reset on every path.
        """
        if self._closed:
            return
        self._closed = True
        # Captured before any reset so diagnostics can name the run.
        run_id = guards.current_run_id()
        try:
            if self._state is not None:
                closed_data: dict[str, str] = {}
                if failed:
                    closed_data["error_type"] = error_type or "WorkflowIncomplete"
                    if error_message:
                        closed_data["message"] = error_message
                closed_event = WorkflowEvent(
                    type="telemetry_closed", timestamp=time.time(), data=closed_data
                )
                self._state.finish_all(closed_event, failed=failed)
                self._state.detach_close_tokens()
                self._state.clear_indexes()
        except Exception:  # noqa: BLE001 -- cleanup must not mask a workflow exception.
            logger.warning("OpenTelemetry span cleanup failed for run %s", run_id, exc_info=True)
        try:
            if self._tracer_provider is not None:
                self._drain_provider(self._tracer_provider, run_id)
        finally:
            guards.reset_telemetry_context()

    def _drain_provider(self, provider: TracerProvider, run_id: str | None) -> None:
        """Flush and shut down the exporter off the calling thread.

        The batch processor's ``force_flush`` ignores its timeout and drains
        synchronously — with a slow or unreachable collector each queued batch
        costs up to the exporter timeout, so doing this on the asyncio thread
        would stall workflow teardown and cancellation. The drain runs on a
        daemon thread bounded by a single overall deadline; an incomplete
        export is reported rather than waited on. The daemon flag plus the
        provider's ``shutdown_on_exit=False`` construction guarantee that
        interpreter shutdown can never block on leftover export work.
        """

        def _drain() -> None:
            try:
                flushed = provider.force_flush(
                    timeout_millis=int(_CLOSE_EXPORT_DEADLINE_SECONDS * 1000)
                )
                if not flushed:
                    logger.warning(
                        "OpenTelemetry force_flush reported incomplete export for run %s; "
                        "some spans may be lost",
                        run_id,
                    )
            except Exception:  # noqa: BLE001
                logger.warning(
                    "OpenTelemetry flush failed for run %s; some spans may be lost",
                    run_id,
                    exc_info=True,
                )
            # Shutdown is attempted independently of the flush outcome.
            try:
                provider.shutdown()
            except Exception:  # noqa: BLE001
                logger.warning(
                    "OpenTelemetry exporter shutdown failed for run %s",
                    run_id,
                    exc_info=True,
                )

        worker = threading.Thread(target=_drain, name="conductor-telemetry-close", daemon=True)
        worker.start()
        worker.join(_CLOSE_EXPORT_DEADLINE_SECONDS)
        if worker.is_alive():
            logger.warning(
                "OpenTelemetry export for run %s did not finish within %.1fs; "
                "continuing teardown, some spans may be lost",
                run_id,
                _CLOSE_EXPORT_DEADLINE_SECONDS,
            )


def _dispatch(state: SpanState, event: WorkflowEvent) -> None:
    """Route an engine event to its narrow lifecycle handler."""
    match event.type:
        case "workflow_started":
            workflows.workflow_started(state, event)
        case "workflow_completed":
            workflows.workflow_completed(state, event)
        case "workflow_failed":
            workflows.workflow_failed(state, event)
        case "parallel_started" | "for_each_started":
            workflows.group_started(state, event)
        case "parallel_completed" | "for_each_completed":
            workflows.group_completed(state, event)
        case "subworkflow_started":
            workflows.subworkflow_started(state, event)
        case "subworkflow_completed":
            workflows.subworkflow_completed(state, event)
        case "subworkflow_failed":
            workflows.subworkflow_failed(state, event)
        case "parallel_agent_started":
            execution.parallel_agent_started(state, event)
        case "parallel_agent_completed":
            execution.parallel_agent_completed(state, event)
        case "parallel_agent_failed":
            execution.parallel_agent_failed(state, event)
        case "for_each_item_started":
            execution.item_started(state, event)
        case "for_each_agent_started":
            execution.item_agent_started(state, event)
        case "for_each_item_completed":
            execution.item_completed(state, event)
        case "for_each_item_failed":
            execution.item_failed(state, event)
        case "agent_started":
            execution.agent_started(state, event)
        case "agent_completed":
            execution.agent_completed(state, event)
        case "agent_failed":
            execution.agent_failed(state, event)
        case "questions_completed":
            execution._finish_agent(state, event, failed=False)
        case "questions_presented":
            pass
        case "script_started" | "set_started" | "wait_started":
            execution.step_started(state, event)
        case "script_completed" | "set_completed" | "wait_completed":
            execution.step_completed(state, event)
        case "script_failed" | "set_failed" | "wait_failed":
            execution.step_failed(state, event)
        case "agent_validator_start":
            execution.validator_started(state, event)
        case "agent_validator_complete":
            execution.validator_completed(state, event)
        case "agent_tool_start":
            execution.tool_started(state, event)
        case "agent_tool_complete":
            execution.tool_completed(state, event)
        case "gate_presented" | "gate_resolved":
            execution.gate_event(state, event)
        case _:
            pass
    state.detach_finished_for_current_task()
