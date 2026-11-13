"""Opt-in instrumentation of the seven unchanged D16 parent exercises only."""

from __future__ import annotations

import time
import weakref
from types import CodeType, FrameType

import psutil
from artifact_policy import UnsafeArtifact
from smoke import long_process
from smoke.long_diagnostics import OwnershipFailure
from smoke.long_ownership import CreatorBindings
from smoke.long_records import ParsedControl, Startup
from smoke.parent_ownership_probe import ActorCase, NativeBoundary
from smoke.parent_resource_records import (
    Assertion,
    Issue,
    Phase,
    Records,
    Refusal,
    Sample,
    Snapshot,
    Stage,
    Timing,
)
from smoke.parent_resource_state import POPEN, State
from smoke.support import ProcessProbe
from smoke.test_readiness_interrupt import resources

PROBE_CLOSE = ProcessProbe.close.__code__
PROBE_RECORD = ProcessProbe.record.__code__


class Trace:
    """Aggregate a code-filtered call trace without retaining frames or changing actors."""

    def __init__(self, records: Records, exercise: CodeType) -> None:
        self.records, self.exercise = records, exercise
        self.state = State(False)
        self.assertion: Assertion = "not-reached"
        self.active = False
        self.samples = 0
        self.count_begin = 0
        self.end_ns: int | None = None
        self.refusal_stage = Refusal.NONE
        self.phases: dict[Phase, Timing] = {}
        self.entered: dict[int, tuple[Phase, int]] = {}
        self.released = False
        self.source_files = {long_process.__file__, "<frozen-D13-long_process>"}
        self.sources_done = False
        self.stages: set[Stage] = set()

    def frame(self, current: FrameType) -> FrameType | None:
        for _ in range(5):
            if current.f_code is self.exercise:
                return current
            if current.f_back is None:
                break
            current = current.f_back
        return None

    def sample(self, stage: Stage, frame: FrameType | None = None) -> None:
        begin = time.monotonic_ns()
        counts = tuple(resources())
        self.snapshot(Sample(stage, begin, (counts[0], counts[1], counts[2])), frame)

    def snapshot(self, sample: Sample, frame: FrameType | None) -> None:
        process = psutil.Process()
        assert hasattr(process, "threads")
        tids = tuple(thread.id for thread in process.threads())
        threads = self.state.threads()
        if len(tids) > 64 or len(threads) > 64:
            self.records.fail(Issue.THREADS)
        boundary = frame.f_locals.get("boundary") if frame is not None else None
        root, refs = self.state.root_row(), self.state.refs(frame)
        self.stages.add(sample.stage)
        self.records.add(
            Snapshot(
                sample.stage,
                sample.begin_ns,
                time.monotonic_ns(),
                sample.counts,
                root,
                refs,
                tuple(self.state.queries.values()),
                threads[:64],
                tids[:64],
                len(boundary.opened) if isinstance(boundary, NativeBoundary) else 0,
                len(boundary.closed) if isinstance(boundary, NativeBoundary) else 0,
                self.assertion,
                self.state.finalization,
                self.state.close_enter,
                self.state.close_return,
                self.state.close_error,
                self.sources_done and self.assertion in ("passed", "failed"),
            )
        )

    def phase(self, frame: FrameType) -> Phase | None:
        name, filename = frame.f_code.co_name, frame.f_code.co_filename
        if filename in self.source_files:
            if name == "run_control":
                return "control"
            if name == "capture":
                return "capture-final" if frame.f_locals.get("scan") == "final" else "capture-run"
        owner = frame.f_locals.get("self")
        if isinstance(owner, CreatorBindings):
            owners: dict[str, Phase] = {"__init__": "bind", "admit": "admit", "finish": "finish"}
            return owners.get(name)
        if frame.f_code is ProcessProbe.bind.__func__.__code__:
            return "bind"
        if filename == self.exercise.co_filename:
            calls: dict[str, Phase] = {
                "parsed": "parse",
                "wait": "wait-control" if self.active else "wait-rescue",
                "stopped": "stop",
            }
            return calls.get(name)
        return None

    def observe[T](self, frame: FrameType, event: str, result: T) -> None:
        now = time.monotonic_ns()
        if event not in ("call", "return"):
            return
        if frame.f_code is self.exercise and event == "call":
            case = frame.f_locals.get("case")
            if isinstance(case, ActorCase):
                self.state.synthetic = case.depth > 0
                self.records.actor = case
        phase = self.phase(frame)
        if phase is not None:
            if event == "call":
                self.entered[id(frame)] = (phase, now)
                if phase == "control":
                    self.active = True
            else:
                timing = self.entered.pop(id(frame), None)
                if timing is not None:
                    label, start = timing
                    self.phases.setdefault(label, Timing()).add(start, now)
                    startup = (
                        result.startup
                        if isinstance(result, ParsedControl)
                        else (frame.f_locals.get("first") if label == "admit" else None)
                    )
                    if isinstance(startup, Startup):
                        roles: dict[tuple[Phase, str], Phase] = {
                            ("parse", "controller"): "parse-controller",
                            ("parse", "gw0"): "parse-gw0",
                            ("admit", "controller"): "admit-controller",
                            ("admit", "gw0"): "admit-gw0",
                        }
                        if role_phase := roles.get((label, startup.role)):
                            self.phases.setdefault(role_phase, Timing()).add(start, now)
                    if (
                        frame.f_code.co_name == "wait"
                        and frame.f_locals.get("released")
                        and not self.released
                    ):
                        self.phases.setdefault("release-window", Timing()).add(start, now)
                        self.released = True
                if phase == "control":
                    failure = frame.f_locals.get("first_failure")
                    if isinstance(failure, OwnershipFailure):
                        self.refusal_stage = Refusal(failure.stage)
                    self.active = False
                    self.sources_done = True
                    self.sample(Stage.CONTROL, self.frame(frame))
        end = frame.f_locals.get("end")
        if self.active and phase == "bind" and frame.f_back is not None:
            end = frame.f_back.f_locals.get("end", end)
        if (
            self.active
            and isinstance(end, float)
            and (
                phase == "bind"
                or (
                    frame.f_code.co_name == "run_control"
                    and frame.f_code.co_filename in self.source_files
                )
            )
        ):
            self.end_ns = round(end * 1_000_000_000)
        if self.active and phase in ("capture-run", "capture-final") and frame.f_back is not None:
            end = frame.f_back.f_locals.get("end")
            if isinstance(end, float):
                self.end_ns = round(end * 1_000_000_000)
        resource_call = (
            frame.f_code is resources.__code__
            and frame.f_back is not None
            and frame.f_back.f_code is self.exercise
        )
        if resource_call and event == "call":
            self.count_begin = now
        if event != "return":
            return
        owner = frame.f_locals.get("self")
        if (
            frame.f_code is POPEN.__init__.__code__
            and self.active
            and isinstance(owner, POPEN)
            and self.state.child is None
            and hasattr(owner, "pid")
        ):
            self.state.child = weakref.ref(owner)
            self.sample(Stage.SPAWN, self.frame(frame))
        if isinstance(owner, CreatorBindings) and frame.f_code.co_name == "__init__":
            self.state.owner = weakref.ref(owner)
            for node in owner.nodes.values():
                self.state.query(node.probe)
        if isinstance(result, ProcessProbe):
            self.state.query(result)
        if isinstance(owner, ProcessProbe) and frame.f_code is PROBE_CLOSE:
            self.state.closes[owner.key] = self.state.closes.get(owner.key, 0) + 1
            self.state.query(owner)
        if isinstance(owner, ProcessProbe) and frame.f_code is PROBE_RECORD:
            self.state.used[owner.key] = now
            self.state.query(owner)
        if resource_call and isinstance(result, list):
            counts = tuple(value for value in result if type(value) is int)
            if len(counts) != 3:
                self.records.fail(Issue.OBSERVATION)
                return
            self.samples += 1
            stage = Stage.BASELINE if self.samples == 1 else Stage.RESCUE
            self.snapshot(
                Sample(stage, self.count_begin, (counts[0], counts[1], counts[2])), frame.f_back
            )
        if frame.f_code is self.exercise:
            self.assertion = (
                "passed"
                if isinstance(result, dict)
                else ("failed" if frame.f_lineno == 215 else "not-reached")
            )
            self.sample(Stage.ASSERTION, frame)

    def profile[T](self, frame: FrameType, event: str, result: T) -> None:
        try:
            self.observe(frame, event, result)
        except (
            OSError,
            psutil.Error,
            UnsafeArtifact,
            AttributeError,
            KeyError,
            TypeError,
            ValueError,
        ):
            self.records.fail(Issue.OBSERVATION)
