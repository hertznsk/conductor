"""Typed event-field readers shared by OpenTelemetry subscriber modules."""

from __future__ import annotations

from typing import NamedTuple

from conductor.events import WorkflowEvent

type PathKey = tuple[str, ...]
type SpanKey = tuple[str, int]
type ToolKey = tuple[PathKey, SpanKey, str]
type AttributeValue = str | bool | int | float


class SubworkflowParent(NamedTuple):
    """A remembered parent span for a not-yet-started child workflow span.

    ``is_item`` records whether the parent is a for-each item span. Item
    spans are terminated by ``for_each_item_completed`` /
    ``for_each_item_failed`` — never by the child's ``subworkflow_completed``
    — so the item's terminal metadata (cost, tokens) can still land on an
    open span.
    """

    span_key: SpanKey
    is_item: bool


def event_path(event: WorkflowEvent, name: str) -> PathKey:
    """Return a string-only path field, or the root path for invalid input."""
    value = event.data.get(name)
    if not isinstance(value, list | tuple):
        return ()
    parts = tuple(part for part in value if isinstance(part, str))
    return parts if len(parts) == len(value) else ()


def event_text(event: WorkflowEvent, name: str) -> str | None:
    """Return a non-empty string field."""
    value = event.data.get(name)
    return value if isinstance(value, str) and value else None


def event_number(event: WorkflowEvent, name: str) -> int | None:
    """Return an integer field while rejecting booleans."""
    value = event.data.get(name)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def timestamp_ns(event: WorkflowEvent) -> int:
    """Convert a workflow event's Unix seconds to OpenTelemetry nanoseconds."""
    return int(event.timestamp * 1_000_000_000)
