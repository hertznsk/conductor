"""Temporary round-4 failure metadata; never retrieves or schedules producer tasks."""

from __future__ import annotations

import asyncio
import json
import sys
from collections import deque
from dataclasses import asdict, dataclass
from logging import LogRecord
from types import AsyncGeneratorType, CoroutineType, GeneratorType, TracebackType
from typing import TYPE_CHECKING, Protocol, TypedDict, runtime_checkable

import pytest

if TYPE_CHECKING:
    from conductor.engine.mcp_lifecycle import McpRunLifecycle


@dataclass(frozen=True, slots=True)
class FrameData:
    file: str
    function: str
    line: int


@dataclass(frozen=True, slots=True)
class ErrorData:
    exception_type: str
    errno: int | None
    winerror: int | None
    frames: list[FrameData]
    truncated: bool


@dataclass(frozen=True, slots=True)
class TaskData:
    role: str
    done: bool
    cancelled: bool
    private_fields_supported: bool
    result_type: str | None
    error: ErrorData | None
    await_chain: list[FrameData]
    log_traceback_before: bool | None
    log_traceback_after: bool | None
    retrieval_unchanged: bool
    truncated: bool


@dataclass(frozen=True, slots=True)
class LogData:
    logger: str
    pathname: str
    line: int
    function: str
    level: int
    error: ErrorData | None
    truncated: bool


@dataclass(frozen=True, slots=True)
class FailureData:
    kind: str
    primary: ErrorData
    marker_set: bool | None
    total: int
    truncated: bool


@dataclass(frozen=True, slots=True)
class MarkerProbe[T]:
    marker: asyncio.Event
    producer: asyncio.Task[T]
    lifecycle: McpRunLifecycle


class Record(TypedDict):
    event: str
    nodeid: str
    phase: str
    traceback: str
    truncated: bool


@runtime_checkable
class Emitter(Protocol):
    def emit(self, record: Record) -> None: ...


def _clip(value: str) -> str:
    return value if len(value) <= 160 else value[:70] + "...[truncated]" + value[-70:]


def _type_name[T](value: T) -> str:
    return _clip(type(value).__module__ + "." + type(value).__qualname__)


def _error(error: BaseException, trace: TracebackType | None = None) -> ErrorData:
    frames: deque[FrameData] = deque(maxlen=6)
    cursor = error.__traceback__ if trace is None else trace
    seen = 0
    while cursor is not None and seen < 64:
        code = cursor.tb_frame.f_code
        frames.append(FrameData(_clip(code.co_filename), _clip(code.co_name), cursor.tb_lineno))
        cursor = cursor.tb_next
        seen += 1
    errno = error.errno if isinstance(error, OSError) else None
    winerror = getattr(error, "winerror", None) if isinstance(error, OSError) else None
    return ErrorData(
        _type_name(error), errno if type(errno) is int else None,
        winerror if type(winerror) is int else None, list(frames), seen > 6 or cursor is not None,
    )


def _task[T](role: str, task: asyncio.Task[T]) -> TaskData:
    # CPython 3.13 is the hosted runtime; 3.14 is the local control runtime.
    supported = (
        sys.implementation.name == "cpython" and sys.version_info[:2] in {(3, 13), (3, 14)}
        and type(task) is asyncio.Task
        and all(hasattr(task, name) for name in ("_exception", "_result", "_log_traceback"))
    )
    before = task._log_traceback if supported else None
    error = task._exception if supported else None
    result_type = (
        _type_name(getattr(task, "_result"))
        if supported and task.done() and not task.cancelled() and error is None else None
    )
    chain = []
    node = task.get_coro()
    while node is not None and len(chain) < 4:
        match node:
            case CoroutineType():
                frame, node = node.cr_frame, node.cr_await
            case GeneratorType():
                frame, node = node.gi_frame, node.gi_yieldfrom
            case AsyncGeneratorType():
                frame, node = node.ag_frame, node.ag_await
            case _:
                break  # A Future iterator has no coroutine frame; never resume it.
        if frame is not None:
            code = frame.f_code
            chain.append(FrameData(_clip(code.co_filename), _clip(code.co_name), frame.f_lineno))
    after = task._log_traceback if supported else None
    return TaskData(
        role, task.done(), task.cancelled(), supported, result_type,
        _error(error) if error is not None else None, chain, before, after, before == after,
        node is not None,
    )


def _emit(request: pytest.FixtureRequest, primary: BaseException,
          data: FailureData | TaskData | LogData) -> None:
    encoded = json.dumps(asdict(data), ensure_ascii=True)
    truncated = data.truncated or "...[truncated]" in encoded or len(encoded) > 6000
    if len(encoded) > 6000:
        encoded = json.dumps({"truncated": True, "prefix": encoded[:2500]})
    # Notes are independent of later cleanup; the existing worker emitter survives masking.
    primary.add_note("WINDOWS_FAILURE_CONTEXT " + encoded)
    reporter = request.config.pluginmanager.get_plugin("f3-passive-reporting")
    if isinstance(reporter, Emitter):
        reporter.emit({"event": "failure.context", "nodeid": request.node.nodeid[:1024],
                       "phase": "call", "traceback": encoded, "truncated": truncated})


def marker_failure[T](request: pytest.FixtureRequest, probe: MarkerProbe[T]) -> None:
    """Snapshot only explicit owners, synchronously, before the caller's original cleanup."""
    primary = sys.exception()
    if primary is None:
        return
    try:
        # Retain only plain snapshots, not tasks, frames, exceptions or their results.
        snapshots = [_task("opening", probe.producer)]
        total = 1
        for index, attempt in enumerate(probe.lifecycle.attempts[:2]):
            if attempt.task is not None:
                total += 1
                if len(snapshots) < 4:
                    snapshots.append(_task(f"preparation-{index}", attempt.task))
            for entry_index, entry in enumerate(attempt.entries[:2]):
                if entry.allocation is not None:
                    total += 1
                    if len(snapshots) < 4:
                        snapshots.append(_task(f"allocation-{index}-{entry_index}", entry.allocation))
        _emit(request, primary, FailureData(
            "marker", _error(primary), probe.marker.is_set(), total,
            total > 4 or len(probe.lifecycle.attempts) > 2,
        ))
        for snapshot in snapshots:
            _emit(request, primary, snapshot)
    except BaseException as diagnostic_error:
        # Observer boundary: a broken diagnostic must not replace the in-flight failure.
        primary.add_note("WINDOWS_FAILURE_CONTEXT observer_error=" + _type_name(diagnostic_error))


def log_failure(request: pytest.FixtureRequest, records: list[LogRecord]) -> None:
    """Describe only offending records; never format their messages or exception values."""
    primary = sys.exception()
    if primary is None:
        return
    try:
        total = sum(record.exc_info is not None for record in records)
        _emit(request, primary, FailureData("log", _error(primary), None, total, total > 4))
        emitted = 0
        for record in records:
            if record.exc_info is None:
                continue
            if emitted == 4:
                break
            _, error, trace = record.exc_info
            _emit(request, primary, LogData(
                _clip(record.name), _clip(record.pathname), record.lineno,
                _clip(record.funcName or ""), record.levelno,
                _error(error, trace) if error is not None else None, False,
            ))
            emitted += 1
    except BaseException as diagnostic_error:
        primary.add_note("WINDOWS_FAILURE_CONTEXT observer_error=" + _type_name(diagnostic_error))
