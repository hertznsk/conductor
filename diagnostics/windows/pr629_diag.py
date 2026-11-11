"""Observation-only pytest phases; a private process-lifetime fd observes interpreter exit."""

from __future__ import annotations

import faulthandler
import os
import sys
import threading
from collections.abc import Generator
from pathlib import Path

import psutil
import pytest
from artifact_policy import Record, UnsafeArtifact, environment_sanitizer
from diagnostic_sink import Sink
from windows_identity import WindowsIdentity
from xdist.workermanage import WorkerController


class Observation:
    """Own diagnostic state only. Failed setup/rearm disables observation, never the test."""

    def __init__(self) -> None:
        self.sink: Sink | None = None
        self.stack_fd: int | None = None
        self.base: Record = {
            "pid": os.getpid(),
            "worker": os.environ.get("PYTEST_XDIST_WORKER", "controller"),
        }
        try:
            root = Path(os.environ["PR629_DIAG_DIR"])
            worker = str(self.base["worker"])
            stem = f"{os.getpid()}-{worker}"
            self.sink = Sink(root / f"{stem}.phase.jsonl", environment_sanitizer())
            if sys.platform == "win32":
                identity = WindowsIdentity.descendant(os.getpid())
                try:
                    birth = str(identity.ticks)
                finally:
                    identity.close()
            else:
                birth = psutil.Process().create_time().hex()
            self.base["identity"] = f"{os.getpid()}:{birth}"
            self.emit({"event": "start", "parent": os.getppid()})
            private = root / "private"
            private.mkdir(exist_ok=True)
            binary = os.O_BINARY if sys.platform == "win32" else 0
            self.stack_fd = os.open(
                private / f"{stem}.stack.txt", os.O_WRONLY | os.O_CREAT | os.O_EXCL | binary, 0o600
            )
            self.arm()
            self.threads("start")
        except (OSError, ValueError, KeyError, psutil.Error, UnsafeArtifact):
            self.fail("setup-unavailable")

    def fail(self, reason: str) -> None:
        if self.sink is not None:
            self.sink.emit({**self.base, "event": "diagnostic.failure", "reason": reason})
            self.sink.fail(reason)
        else:
            try:
                if sys.__stderr__ is not None:
                    os.write(sys.__stderr__.fileno(), b"Diagnostic evidence is incomplete.\n")
            except (OSError, ValueError, AttributeError):
                return

    def emit(self, record: Record) -> None:
        if self.sink is not None:
            self.sink.emit({**self.base, **record})

    def arm(self) -> None:
        if self.stack_fd is not None:
            try:
                faulthandler.dump_traceback_later(60, repeat=True, file=self.stack_fd, exit=False)
                self.emit({"event": "stack-arm", "stack_armed": True})
            except (OSError, ValueError, RuntimeError):
                self.fail("stack-arm-unavailable")

    def threads(self, stage: str) -> None:
        for thread in threading.enumerate():
            self.emit(
                {
                    "event": "thread",
                    "stage": stage,
                    "name": thread.name,
                    "ident": thread.ident,
                    "native_id": thread.native_id,
                    "daemon": thread.daemon,
                }
            )


OBSERVATION = Observation()


def pytest_configure(config: pytest.Config) -> None:
    OBSERVATION.emit(
        {
            "event": "configured",
            "executable": sys.executable,
            "argv": list(config.invocation_params.args),
            "numprocesses": config.getoption("numprocesses", default=0),
            "dist": config.getoption("dist", default="no"),
            "marker": config.getoption("markexpr"),
            "verbosity": config.getoption("verbose"),
            "durations": config.getoption("durations"),
            "durations_min": config.getoption("durations_min"),
            "cacheprovider": config.pluginmanager.hasplugin("cacheprovider"),
            "faulthandler_zero": float(config.getini("faulthandler_timeout")) == 0,
            "cov_source": config.getoption("cov_source", default=None),
        }
    )


def pytest_collection_finish(session: pytest.Session) -> None:
    for item in session.items:
        OBSERVATION.emit({"event": "collected", "nodeid": item.nodeid})
    OBSERVATION.emit({"event": "configured", "collected": len(session.items)})


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_setup(item: pytest.Item) -> Generator[None]:
    OBSERVATION.emit({"event": "setup.begin", "nodeid": item.nodeid})
    try:
        yield
    finally:
        OBSERVATION.emit({"event": "setup.end", "nodeid": item.nodeid})


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_call(item: pytest.Item) -> Generator[None]:
    OBSERVATION.emit({"event": "call.begin", "nodeid": item.nodeid})
    try:
        yield
    finally:
        OBSERVATION.emit({"event": "call.end", "nodeid": item.nodeid})


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_teardown(item: pytest.Item) -> Generator[None]:
    OBSERVATION.emit({"event": "teardown.begin", "nodeid": item.nodeid})
    try:
        yield
    finally:
        OBSERVATION.emit({"event": "teardown.end", "nodeid": item.nodeid})


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_protocol(item: pytest.Item) -> Generator[None]:
    OBSERVATION.emit({"event": "runtest.begin", "nodeid": item.nodeid})
    try:
        yield
    finally:
        OBSERVATION.emit({"event": "runtest.end", "nodeid": item.nodeid})


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    OBSERVATION.emit(
        {
            "event": "report",
            "nodeid": report.nodeid,
            "phase": report.when,
            "outcome": report.outcome,
        }
    )


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_sessionfinish(session: pytest.Session) -> Generator[None]:
    OBSERVATION.emit({"event": "sessionfinish.begin", "exitcode": int(session.exitstatus)})
    OBSERVATION.threads("sessionfinish.begin")
    try:
        yield
    finally:
        OBSERVATION.emit({"event": "sessionfinish.end", "exitcode": int(session.exitstatus)})
        OBSERVATION.threads("sessionfinish.end")


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_unconfigure() -> Generator[None]:
    OBSERVATION.emit({"event": "unconfigure.begin"})
    try:
        yield
    finally:
        OBSERVATION.arm()
        OBSERVATION.emit({"event": "unconfigure.end"})
        # Both fds deliberately remain alive until physical interpreter exit.


@pytest.hookimpl(optionalhook=True)
def pytest_testnodedown(node: WorkerController, error: str | None) -> None:
    OBSERVATION.emit({"event": "worker-down", "name": node.gateway.id, "failed": error is not None})


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_exception_interact() -> Generator[None]:
    try:
        yield
    finally:
        OBSERVATION.arm()


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_terminal_summary() -> Generator[None]:
    OBSERVATION.emit({"event": "summary.begin"})
    try:
        yield
    finally:
        OBSERVATION.emit({"event": "summary.end"})
