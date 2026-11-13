"""Closed, bounded stderr records for the single parent ownership experiment."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Final, Literal

from _pytest.capture import CaptureManager
from artifact_policy import Sanitizer, UnsafeArtifact
from smoke.parent_ownership_probe import ActorCase

RECORD_LIMIT: Final = 4096
BYTE_LIMIT: Final = 128 * 1024
CASE_LIMIT: Final = 32
TOTAL_LIMIT: Final = 224
RESERVE: Final = 256
PREFIX: Final = "PR629_PARENT_RESOURCE "
type Origin = Literal["synthetic", "real-owned", "real-borrowed"]
type ThreadSource = Literal["other", "stdout_thread", "stderr_thread", "_stdin_thread"]
type Assertion = Literal["not-reached", "passed", "failed"]
type Finalization = Literal[
    "not-attempted", "unsafe-not-attempted", "windows-unrun", "close-failed", "close-returned"
]
type Phase = Literal[
    "bind",
    "admit",
    "finish",
    "parse",
    "wait-control",
    "wait-rescue",
    "stop",
    "control",
    "capture-run",
    "capture-final",
    "release-window",
    "parse-controller",
    "parse-gw0",
    "admit-controller",
    "admit-gw0",
]


class Stage(StrEnum):
    BASELINE = "before-baseline"
    SPAWN = "after-spawn"
    CONTROL = "after-control"
    RESCUE = "after-rescue"
    ASSERTION = "after-assertion"
    FINAL = "after-owner-finalization"


class Issue(StrEnum):
    NONE = "none"
    RECORD = "record-cap"
    CASE = "case-cap"
    TOTAL = "total-cap"
    BYTES = "byte-cap"
    THREADS = "thread-cap"
    OBSERVATION = "observation-failed"
    PROFILE = "profile-already-active"
    SANITIZER = "sanitizer-refused"
    DELIVERY = "delivery-failed"
    STAGES = "stages-incomplete"
    FINALIZATION = "finalization-incomplete"


class Refusal(StrEnum):
    NONE = "none"
    OPEN = "open"
    READ = "read"
    PARSE = "startup-parse"
    LOOKUP = "process-lookup"
    BIRTH_QUERY = "birth-query"
    BIRTH_CHECK = "birth-check"
    PARENT_QUERY = "parent-query"
    PARENT_CHECK = "parent-check"
    BIND = "bind"
    KEY = "key-check"
    CLOSE = "candidate-close"


@dataclass(frozen=True, slots=True)
class Sample:
    stage: Stage
    begin_ns: int
    counts: tuple[int, int, int]


@dataclass(frozen=True, slots=True)
class Root:
    pid: int
    handle: str | None
    closed: bool | None
    returncode: int | None
    flags_ok: bool | None
    flags: int | None
    winerror: int | None
    native_pid: int | None
    ticks: str | None
    io_closed: bool


@dataclass(frozen=True, slots=True)
class Query:
    pid: int
    key: str
    origin: Origin
    handle: str
    borrowed_root_match: bool | None
    owned: bool
    closed: bool
    close_error: int | None
    closes: int
    flags: int | None
    flags_at_ns: int | None
    source_last_query_ns: int | None


@dataclass(frozen=True, slots=True)
class Thread:
    source: ThreadSource
    ident: int | None
    native_id: int | None
    started: bool
    daemon: bool
    current: bool
    join_enter: int | None = None
    join_return: int | None = None
    alive: bool | None = None


@dataclass(frozen=True, slots=True)
class Refs:
    frame_available: bool
    roots_hold: bool
    owner_holds: bool
    wait_captures: bool
    patch_holds: bool
    primary_traceback: bool


@dataclass(frozen=True, slots=True)
class Snapshot:
    stage: Stage
    begin_ns: int
    end_ns: int
    resources: tuple[int, int, int]
    root: Root | None
    refs: Refs
    queries: tuple[Query, ...]
    threads: tuple[Thread, ...]
    tids: tuple[int, ...]
    synthetic_opens: int
    synthetic_closes: int
    assertion: Assertion
    finalization: Finalization
    close_enter: int | None
    close_return: int | None
    close_error: int | None
    borrowers_quiescent: bool


@dataclass(slots=True)
class Timing:
    """Accumulate only bounded scalar intervals, never frames or per-poll records."""

    count: int = 0
    first_ns: int = 0
    first_end_ns: int = 0
    last_ns: int = 0
    total_ns: int = 0
    max_ns: int = 0

    def add(self, start: int, end: int) -> None:
        self.count += 1
        self.first_ns = self.first_ns or start
        self.first_end_ns = self.first_end_ns or end
        self.last_ns = end
        self.total_ns += end - start
        self.max_ns = max(self.max_ns, end - start)


@dataclass(frozen=True, slots=True)
class Phases:
    phases: dict[Phase, Timing]
    control_end_ns: int | None
    refusal_stage: Refusal


class Budget:
    """Account for all seven cases, reserving each terminal status before data."""

    def __init__(self) -> None:
        self.records = 0
        self.bytes = 0
        self.cases = 0


class Records:
    """Buffer capped observations until the original assertion has executed."""

    def __init__(self, budget: Budget, sanitizer: Sanitizer) -> None:
        budget.cases += 1
        self.case = budget.cases
        self.budget, self.sanitizer = budget, sanitizer
        self.lines: list[str] = []
        self.sent = 0
        self.delivery_failed = False
        self.issue = Issue.NONE
        self.actor: ActorCase | None = None

    def fail(self, issue: Issue) -> None:
        if self.issue == Issue.NONE:
            self.issue = issue

    def add(self, row: Snapshot | Phases) -> None:
        if self.issue != Issue.NONE:
            return
        line = (
            PREFIX
            + json.dumps(
                {
                    "case": self.case,
                    "actor": asdict(self.actor) if self.actor else None,
                    **asdict(row),
                },
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
            )
            + "\n"
        )
        size = len(line.encode("ascii"))
        for exceeded, issue in (
            (size > RECORD_LIMIT, Issue.RECORD),
            (len(self.lines) >= CASE_LIMIT - 2, Issue.CASE),
            (self.budget.records >= TOTAL_LIMIT - 14, Issue.TOTAL),
            (self.budget.bytes + size > BYTE_LIMIT - 7 * RESERVE, Issue.BYTES),
        ):
            if exceeded:
                self.fail(issue)
                return
        try:
            self.sanitizer.published(line, RECORD_LIMIT)
        except UnsafeArtifact:
            self.fail(Issue.SANITIZER)
            return
        self.lines.append(line)
        self.budget.records += 1
        self.budget.bytes += size

    def finish(self) -> None:
        terminal = {"case": self.case, "terminal": True, "incomplete": self.issue.value}
        line = f"{PREFIX}{json.dumps(terminal, separators=(',', ':'))}\n"
        try:
            self.sanitizer.published(line, RESERVE)
        except UnsafeArtifact:
            self.fail(Issue.SANITIZER)
            line = PREFIX + '{"terminal":true,"incomplete":"sanitizer-refused"}\n'
        self.lines.append(line)
        self.budget.records += 1
        self.budget.bytes += len(line)

    def flush(self, capture: CaptureManager, primary: BaseException | None) -> None:
        if self.delivery_failed:
            return
        try:
            with capture.global_and_fixture_disabled():
                sys.stderr.write("".join(self.lines[self.sent :]))
                sys.stderr.flush()
            self.sent = len(self.lines)
        except (OSError, ValueError, KeyboardInterrupt) as error:
            self.delivery_failed = True
            if isinstance(error, KeyboardInterrupt) and primary is None:
                raise
            self.fail(Issue.DELIVERY)
            if primary is not None:
                primary.add_note("PR629 parent resource diagnostic delivery failed.")
            else:
                message = "PR629_PARENT_RESOURCE_INCOMPLETE delivery-failed"
                self.budget.records += 1
                self.budget.bytes += len(message) + 1
                with capture.global_and_fixture_disabled():
                    print(message, file=sys.__stderr__)
