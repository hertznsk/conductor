"""Explicit pytest plugin for the two long controls."""

from __future__ import annotations

import os
from collections.abc import Generator
from pathlib import Path

import pytest
from smoke.long_capture import Probe
from smoke.long_protocol import ROLES
from xdist.workermanage import WorkerController

_PROBE = (
    Probe(Path(os.environ["PR629_LONG_PROBE_DIR"]))
    if "PR629_LONG_PROBE_DIR" in os.environ
    else None
)


def pytest_configure(config: pytest.Config) -> None:
    if _PROBE is not None:
        try:
            _PROBE.configuration(config)
        except (OSError, ValueError, RuntimeError):
            _PROBE.emit(
                {
                    "event": "scope",
                    "kind": "configuration",
                    "stage": "config",
                    "name": "config-query",
                    "status": "unknown",
                }
            )
            _PROBE.snapshot("config")


def pytest_collection_finish(session: pytest.Session) -> None:
    if _PROBE is not None:
        _PROBE.collected = len(session.items)
        _PROBE.emit(
            {
                "event": "scope",
                "kind": "configuration",
                "stage": "collection",
                "name": "isolated_paths-all",
                "complete": all(
                    isinstance(item, pytest.Function) and "isolated_paths" in item.fixturenames
                    for item in session.items
                )
                if session.items
                else None,
            }
        )
        _PROBE.snapshot("collection")


@pytest.hookimpl(optionalhook=True)
def pytest_xdist_node_collection_finished(node: WorkerController, ids: list[str]) -> None:
    if _PROBE is not None:
        _PROBE.collected = len(ids)
        _PROBE.snapshot("collection")


@pytest.hookimpl(wrapper=True, trylast=True)
def pytest_runtest_makereport(
    item: pytest.Item,
    call: pytest.CallInfo[None],
) -> Generator[None, pytest.TestReport, pytest.TestReport]:
    report = yield
    if _PROBE is not None and report.failed:
        _PROBE.exception(call.excinfo.value if call.excinfo is not None else None, report.when)
    return report


@pytest.hookimpl(trylast=True)
def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    if _PROBE is not None:
        phase = (
            report.when
            if isinstance(report.when, str) and report.when in ("setup", "call", "teardown")
            else "internal"
        )
        _PROBE.counts[phase, report.outcome] += 1
        if report.failed and _PROBE.base["role"] == "controller":
            _PROBE.exception(None, phase)
        if (
            phase == "teardown"
            and sum(n for (phase, _), n in _PROBE.counts.items() if phase == "teardown") % 1024 == 0
        ):
            _PROBE.snapshot("checkpoint")


def pytest_collectreport(report: pytest.CollectReport) -> None:
    if _PROBE is not None and report.failed:
        _PROBE.emit(
            {
                "event": "scope",
                "kind": "collection-report",
                "stage": "collection-report",
                "failed": True,
                "exception_type": "unknown",
            }
        )


def pytest_exception_interact(
    node: pytest.Collector,
    call: pytest.CallInfo[None],
    report: pytest.CollectReport,
) -> None:
    if _PROBE is not None and isinstance(report, pytest.CollectReport) and call.excinfo is not None:
        _PROBE.exception(call.excinfo.value, "collection")


def pytest_internalerror(excinfo: pytest.ExceptionInfo[BaseException]) -> None:
    if _PROBE is not None:
        _PROBE.exception(excinfo.value, "internal")


@pytest.hookimpl(optionalhook=True)
def pytest_testnodedown(node: WorkerController, error: str | None) -> None:
    if _PROBE is not None:
        name = node.gateway.id if node.gateway.id in ROLES else "unknown"
        _PROBE.emit(
            {
                "event": "worker-down",
                "kind": "worker-down",
                "stage": "worker-down",
                "name": name,
                "failed": error is not None,
            }
        )
        _PROBE.snapshot("worker-down")


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_sessionfinish(session: pytest.Session) -> Generator[None]:
    if _PROBE is not None:
        _PROBE.snapshot("sessionfinish.begin")
    try:
        yield
    finally:
        if _PROBE is not None:
            _PROBE.emit(
                {
                    "event": "observed",
                    "kind": "process",
                    "stage": "sessionfinish.end",
                    "exitcode": int(session.exitstatus),
                }
            )
            _PROBE.snapshot("sessionfinish.end")


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_unconfigure() -> Generator[None]:
    if _PROBE is not None:
        _PROBE.snapshot("unconfigure.begin")
    try:
        yield
    finally:
        if _PROBE is not None:
            _PROBE.snapshot("unconfigure.end")
            _PROBE.sink.close()


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_terminal_summary() -> Generator[None]:
    if _PROBE is not None:
        _PROBE.snapshot("summary.begin")
    try:
        yield
    finally:
        if _PROBE is not None:
            _PROBE.snapshot("summary.end")
