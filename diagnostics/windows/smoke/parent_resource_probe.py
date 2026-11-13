"""Opt-in pytest delivery of one bounded parent resource experiment."""

from __future__ import annotations

import sys
from collections.abc import Generator
from contextlib import contextmanager
from types import CodeType

import psutil
import pytest
from _pytest.capture import CaptureManager
from artifact_policy import UnsafeArtifact, environment_sanitizer
from smoke.parent_resource_records import Budget, Issue, Phases, Records, Stage
from smoke.parent_resource_trace import Trace


class Probe:
    """Own the profile subscription and post-assertion diagnostic finalization."""

    def __init__(self, records: Records, exercise: CodeType) -> None:
        self.records = records
        self.trace = Trace(records, exercise)

    def complete(self, primary: BaseException | None, capture: CaptureManager) -> None:
        self.records.flush(capture, primary)
        try:
            self.trace.state.finalize(
                self.trace.sources_done
                and self.trace.assertion in ("passed", "failed")
                and self.trace.samples == 2
                and Stage.ASSERTION in self.trace.stages
                and self.records.issue == Issue.NONE
            )
            self.trace.sample(Stage.FINAL)
            self.records.add(Phases(self.trace.phases, self.trace.end_ns, self.trace.refusal_stage))
            if self.trace.stages != set(Stage):
                self.records.fail(Issue.STAGES)
            if self.trace.state.finalization in ("unsafe-not-attempted", "close-failed"):
                self.records.fail(Issue.FINALIZATION)
        except KeyboardInterrupt:
            self.records.fail(Issue.OBSERVATION)
            if primary is None:
                raise
            primary.add_note("PR629 parent resource diagnostic finalization interrupted.")
        except (
            OSError,
            psutil.Error,
            UnsafeArtifact,
            AttributeError,
            TypeError,
            ValueError,
            RuntimeError,
        ):
            self.records.fail(Issue.OBSERVATION)
        finally:
            self.records.finish()
            self.records.flush(capture, primary)

    @contextmanager
    def observing(self, capture: CaptureManager) -> Generator[None]:
        previous = sys.getprofile()
        if previous is None:
            sys.setprofile(self.trace.profile)
        else:
            self.records.fail(Issue.PROFILE)
        try:
            yield
        finally:
            sys.setprofile(previous)
            self.complete(sys.exception(), capture)


@pytest.fixture(scope="session")
def parent_resource_budget() -> Budget:
    return Budget()


@pytest.hookimpl(wrapper=True)
def pytest_runtest_call(item: pytest.Item) -> Generator[None, None, None]:
    if not isinstance(item, pytest.Function):
        yield
        return
    module = item.module
    if module is None or module.__name__.split(".")[-1] != "test_parent_ownership":
        yield
        return
    budget = item._request.getfixturevalue("parent_resource_budget")
    capture = item.config.pluginmanager.getplugin("capturemanager")
    if not isinstance(budget, Budget) or not isinstance(capture, CaptureManager):
        raise UnsafeArtifact("parent-resource-probe-pytest-context")
    records = Records(budget, environment_sanitizer())
    probe = Probe(records, module.exercise.__code__)
    with probe.observing(capture):
        yield
