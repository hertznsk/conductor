"""Passive ordinary-lane reporting; missing session.finish means incomplete evidence.

Files are per process, closed after each record, and never prove native process exit.
Only the controller streams reports to stdout. Workers retain phase starts locally.
No captured output, environment, locals, scheduling or TestReport fields are changed.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Final, Protocol, TypedDict

import pytest

FILE_CAP: Final = 32 * 1024 * 1024
STDOUT_CAP: Final = 16 * 1024 * 1024
NODE_CAP: Final = 1024
TRACE_CAP: Final = 8192


class Gateway(Protocol):
    id: str


class Worker(Protocol):
    gateway: Gateway


class Record(TypedDict, total=False):
    event: str
    sequence: int
    monotonic: float
    pid: int
    worker: str
    nodeid: str
    phase: str
    outcome: str
    traceback: str
    truncated: bool
    collected: int
    session_exitstatus: int
    stream_complete: bool


def clipped(text: str, limit: int) -> str:
    """Retain both traceback location and final assertion when a field is oversized."""
    if len(text) <= limit:
        return text
    marker = "...[truncated]..."
    half = (limit - len(marker)) // 2
    return text[:half] + marker + text[-half:]


class Reporter:
    """Accumulate only reporting counters; all writes have separate finite budgets."""

    def __init__(self, root: Path, worker: str) -> None:
        self.worker = worker
        self.path = root / f"{worker}.jsonl"
        self.sequence = 0
        self.file_bytes = 0
        self.stdout_bytes = 0
        self.file_enabled = worker in ("controller", "gw0", "gw1")
        self.stdout_enabled = worker == "controller"
        self.incomplete = False
        self.warned = False
        if self.file_enabled:
            try:
                with self.path.open("xb"):
                    pass
            except OSError:
                self.file_enabled = False
                self.notice("file-open")
        else:
            # Restarts remain pytest's decision; only extra reporting files are refused.
            self.notice("worker-file-budget")
        self.emit({"event": "session.start", "stream_complete": False})

    def notice(self, reason: str) -> None:
        """Latch incomplete evidence without changing pytest's outcome or exit status."""
        self.incomplete = True
        if self.warned:
            return
        self.warned = True
        message = f"F3_REPORT_INCOMPLETE {reason}; no native-exit claim.\n"
        try:
            (self.path.parent / "reporting.incomplete").write_text(message, encoding="ascii")
        except OSError:
            message = "F3_REPORT_INCOMPLETE latch-write-failed; " + message
        try:
            if sys.__stderr__ is not None:
                if sys.__stderr__.write(message) != len(message):
                    raise OSError("short reporting stderr write")
                sys.__stderr__.flush()
        except (OSError, ValueError):
            try:
                (self.path.parent / "reporting.incomplete").write_text(
                    "F3_REPORT_INCOMPLETE stderr-write; " + message, encoding="ascii"
                )
            except OSError:
                return  # Neither sink is usable; never recurse or retry the broken console.

    def emit(self, record: Record) -> None:
        record = {
            "sequence": self.sequence,
            "monotonic": time.monotonic(),
            "pid": os.getpid(),
            "worker": self.worker,
            **record,
        }
        self.sequence += 1
        if record.get("truncated"):
            self.incomplete = True
        payload = (json.dumps(record, ensure_ascii=True) + "\n").encode("ascii")
        if self.file_enabled:
            if self.file_bytes + len(payload) > FILE_CAP:
                self.file_enabled = False
                self.notice("file-cap")
            else:
                try:
                    with self.path.open("ab") as stream:
                        if stream.write(payload) != len(payload):
                            raise OSError("short reporting write")
                    self.file_bytes += len(payload)
                except OSError:
                    self.file_enabled = False
                    self.notice("file-write")
        if self.stdout_enabled:
            line = "F3_REPORT " + payload.decode("ascii")
            if self.stdout_bytes + len(line) + 1 > STDOUT_CAP:
                self.stdout_enabled = False
                self.notice("stdout-cap")
            else:
                try:
                    if sys.__stdout__ is None:
                        raise OSError("reporting stdout unavailable")
                    text = "\n" + line
                    written = sys.__stdout__.write(text)
                    # Text writes count characters; the reporter payload is ASCII.
                    self.stdout_bytes += len(text[:written].encode("ascii"))
                    if written != len(text):
                        raise OSError("short reporting stdout write")
                    sys.__stdout__.flush()
                except (OSError, ValueError):
                    self.stdout_enabled = False
                    self.notice("stdout-write")

    def pytest_runtest_logstart(self, nodeid: str) -> None:
        # xdist's controller logstart hook does not carry worker identity.
        self.emit(
            {
                "event": "node.start",
                "nodeid": clipped(nodeid, NODE_CAP),
                "truncated": len(nodeid) > NODE_CAP,
            }
        )

    @pytest.hookimpl(tryfirst=True)
    def pytest_runtest_setup(self, item: pytest.Item) -> None:
        self.begin(item, "setup")

    @pytest.hookimpl(tryfirst=True)
    def pytest_runtest_call(self, item: pytest.Item) -> None:
        self.begin(item, "call")

    @pytest.hookimpl(tryfirst=True)
    def pytest_runtest_teardown(self, item: pytest.Item) -> None:
        self.begin(item, "teardown")

    def begin(self, item: pytest.Item, phase: str) -> None:
        self.emit(
            {
                "event": "phase.begin",
                "nodeid": clipped(item.nodeid, NODE_CAP),
                "phase": phase,
                "truncated": len(item.nodeid) > NODE_CAP,
            }
        )

    @pytest.hookimpl(tryfirst=True)
    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        # Custom longrepr implementations are an optional-observer exception boundary.
        # They must not turn a genuine assertion failure into a pytest INTERNALERROR.
        try:
            trace = str(report.longrepr) if report.failed else ""
            self.emit(
                {
                    "event": "phase.report",
                    "worker": getattr(report, "worker_id", self.worker),
                    "nodeid": clipped(report.nodeid, NODE_CAP),
                    "phase": report.when,
                    "outcome": report.outcome,
                    "traceback": clipped(trace, TRACE_CAP),
                    "truncated": len(trace) > TRACE_CAP or len(report.nodeid) > NODE_CAP,
                }
            )
        except Exception:
            self.notice("report-render")

    @pytest.hookimpl(optionalhook=True)
    def pytest_testnodeready(self, node: Worker) -> None:
        self.emit({"event": "worker.ready", "worker": node.gateway.id})

    @pytest.hookimpl(optionalhook=True)
    def pytest_testnodedown(self, node: Worker) -> None:
        self.emit({"event": "worker.down", "worker": node.gateway.id})

    @pytest.hookimpl(optionalhook=True)
    def pytest_xdist_node_collection_finished(self, node: Worker, ids: list[str]) -> None:
        self.emit({"event": "worker.collected", "worker": node.gateway.id, "collected": len(ids)})

    def pytest_sessionfinish(self, exitstatus: int) -> None:
        self.emit(
            {
                "event": "session.finish",
                "session_exitstatus": int(exitstatus),
                "stream_complete": not self.incomplete,
            }
        )


def pytest_configure(config: pytest.Config) -> None:
    """Opt in explicitly; registration is independent of test collection and execution."""
    if root := os.environ.get("F3_REPORT_DIR"):
        worker = getattr(config, "workerinput", {}).get("workerid", "controller")
        config.pluginmanager.register(Reporter(Path(root), worker), "f3-passive-reporting")
