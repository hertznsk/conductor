"""Local Linux checks for probe delivery and bounds; no substituted Windows API."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import threading
from contextlib import ExitStack, nullcontext
from pathlib import Path

import pytest
from _pytest.capture import CaptureManager
from artifact_policy import Sanitizer
from smoke import long_process
from smoke.parent_ownership_probe import ActorCase
from smoke.parent_resource_probe import Probe
from smoke.parent_resource_records import Budget, Issue, Phase, Phases, Records, Refusal, Timing
from smoke.parent_resource_state import State
from smoke.test_parent_ownership import exercise


def test_phase_aggregate_keeps_first_interval() -> None:
    # Requirement: later binds or waits cannot overwrite the measured initial interval.
    timing = Timing()
    timing.add(10, 14)
    timing.add(30, 37)
    assert (timing.first_ns, timing.first_end_ns, timing.last_ns) == (10, 14, 37)
    assert (timing.count, timing.total_ns, timing.max_ns) == (2, 11, 7)


def test_record_and_case_caps_report_incomplete() -> None:
    # Requirement: reserve terminal and delivery-failure slots within the 32-record case cap.
    large = Records(Budget(), Sanitizer({}))
    large.add(Phases({"bind": Timing(count=10**4100)}, None, Refusal.NONE))
    large.finish()
    small = Records(Budget(), Sanitizer({}))
    for _ in range(32):
        small.add(Phases({}, None, Refusal.NONE))
    small.finish()
    assert large.issue == Issue.RECORD
    assert small.issue == Issue.CASE
    assert len(small.lines) == 31
    for receipt in (large, small):
        assert all(len(line.encode("ascii")) <= 4096 for line in receipt.lines)
        assert json.loads(receipt.lines[-1].split(" ", 1)[1])["incomplete"] == receipt.issue.value


@pytest.mark.parametrize("wide", [False, True])
def test_seven_cases_share_record_and_byte_caps(wide: bool) -> None:
    # Requirement: all cases share the 224-record and 128-KiB caps including terminal receipts.
    budget = Budget()
    receipts = []
    phases: dict[Phase, Timing] = {"bind": Timing(count=10**1900)} if wide else {}
    for _ in range(7):
        receipt = Records(budget, Sanitizer({}))
        for _ in range(31):
            receipt.add(Phases(phases, None, Refusal.NONE))
        receipt.finish()
        receipts.append(receipt)
    assert any(row.issue == (Issue.BYTES if wide else Issue.TOTAL) for row in receipts)
    assert sum(len(row.lines) for row in receipts) <= 224
    assert sum(len(line.encode("ascii")) for row in receipts for line in row.lines) <= 128 * 1024
    assert all(len(row.lines) <= 32 for row in receipts)


def test_sanitizer_refuses_secret_projection() -> None:
    # Requirement: an exact secret match withholds the data and retains a finite refusal receipt.
    receipt = Records(Budget(), Sanitizer({"SECRET": "123456789"}))
    receipt.add(Phases({"bind": Timing(count=123456789)}, None, Refusal.NONE))
    receipt.finish()
    assert receipt.issue == Issue.SANITIZER
    assert len(receipt.lines) == 1
    assert "123456789" not in "".join(receipt.lines)


def test_failed_full_batch_has_one_bounded_fallback(
    monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> None:
    # Requirement: an ambiguously written full batch is never replayed and fits both wire caps.
    capture = request.config.pluginmanager.getplugin("capturemanager")
    assert isinstance(capture, CaptureManager)
    receipt = Records(Budget(), Sanitizer({}))
    for _ in range(30):
        receipt.add(Phases({}, None, Refusal.NONE))
    receipt.finish()

    class AmbiguousOutput(io.StringIO):
        def write(self, text: str) -> int:
            super().write(text)
            raise BrokenPipeError

    with AmbiguousOutput() as output, io.StringIO() as fallback:
        with monkeypatch.context() as patch:
            patch.setattr(capture, "global_and_fixture_disabled", nullcontext)
            patch.setattr(sys, "stderr", output)
            patch.setattr(sys, "__stderr__", fallback)
            receipt.flush(capture, None)
            receipt.flush(capture, None)
        wire = output.getvalue() + fallback.getvalue()
    assert receipt.issue == Issue.DELIVERY
    assert len(wire.splitlines()) == 32
    assert len(wire.encode("ascii")) <= 128 * 1024
    assert wire.count("PR629_PARENT_RESOURCE_INCOMPLETE delivery-failed") == 1


def test_thread_snapshot_does_not_call_liveness(monkeypatch: pytest.MonkeyPatch) -> None:
    # Requirement: pre-assertion observation must not join or call is_alive on a foreign thread.
    release = threading.Event()
    thread = threading.Thread(target=release.wait)
    thread.start()

    def forbidden() -> bool:
        raise AssertionError("Foreign liveness must remain untouched.")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(thread, "is_alive", forbidden)
            rows = State(False).threads()
        assert any(row.native_id == thread.native_id and row.source == "other" for row in rows)
        assert all(row.join_enter is None and row.alive is None for row in rows)
    finally:
        release.set()
        thread.join()


def test_delivery_failure_preserves_primary_assertion(
    monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> None:
    # Requirement: diagnostic output failure cannot replace the original primary AssertionError.
    capture = request.config.pluginmanager.getplugin("capturemanager")
    assert isinstance(capture, CaptureManager)
    receipt = Records(Budget(), Sanitizer({}))
    receipt.add(Phases({}, None, Refusal.NONE))
    probe = Probe(receipt, test_delivery_failure_preserves_primary_assertion.__code__)
    primary = AssertionError("original-resource-assertion")

    class CountedOutput(io.StringIO):
        writes = 0

        def write(self, text: str) -> int:
            self.writes += 1
            return super().write(text)

    closed = CountedOutput()
    closed.close()
    previous = sys.getprofile()
    with monkeypatch.context() as patch:
        patch.setattr(capture, "global_and_fixture_disabled", nullcontext)
        patch.setattr(sys, "stderr", closed)
        with pytest.raises(AssertionError) as caught, probe.observing(capture):
            raise primary
    assert caught.value is primary
    assert sys.getprofile() is previous
    assert receipt.issue == Issue.DELIVERY
    assert primary.__notes__
    assert closed.writes == 1


def test_real_exercise_delivers_six_stages_without_changing_outcome(tmp_path: Path) -> None:
    # Requirement: the real parent actor emits all six bounded stages and retains its original PASS.
    service = Path(__file__).resolve().parents[3]
    target = service / "diagnostics/windows/smoke/test_parent_ownership.py"
    result = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-p",
            "smoke.parent_resource_probe",
            f"--basetemp={tmp_path / 'nested-state'}",
            f"{target}::test_real_original_root_alias_old_new[new]",
            "-q",
        ],
        cwd=service,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        timeout=240,
    )
    assert result.returncode == 0, result.stderr.decode()
    lines = [
        line for line in result.stderr.splitlines() if line.startswith(b"PR629_PARENT_RESOURCE ")
    ]
    rows = [json.loads(line.split(b" ", 1)[1]) for line in lines]
    snapshots = [row for row in rows if "stage" in row]
    assert [row["stage"] for row in snapshots] == [
        "before-baseline",
        "after-spawn",
        "after-control",
        "after-rescue",
        "after-assertion",
        "after-owner-finalization",
    ]
    assert rows[-1]["terminal"] and rows[-1]["incomplete"] == "none"
    assert snapshots[-2]["assertion"] == "passed"
    assert snapshots[-1]["finalization"] == "windows-unrun"
    assert snapshots[0]["resources"] == snapshots[3]["resources"]
    assert all(row["root"]["handle"] is None for row in snapshots[1:])
    assert all(t["alive"] is None for row in snapshots[:5] for t in row["threads"])
    phases = next(row for row in rows if "phases" in row)
    assert phases["control_end_ns"] is not None
    assert {"bind", "parse", "admit", "wait-control", "stop", "finish", "capture-final"} <= set(
        phases["phases"]
    )
    assert {"parse-controller", "admit-controller"} <= set(phases["phases"])
    assert len(lines) <= 32 and all(len(line) + 1 <= 4096 for line in lines)


def test_diagnostic_interrupt_preserves_existing_primary(
    monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> None:
    # Requirement: an interrupt during optional diagnostics cannot replace an existing assertion.
    capture = request.config.pluginmanager.getplugin("capturemanager")
    assert isinstance(capture, CaptureManager)
    receipt = Records(Budget(), Sanitizer({}))
    probe = Probe(receipt, test_diagnostic_interrupt_preserves_existing_primary.__code__)
    primary = AssertionError("original-resource-assertion")

    def interrupt(permitted: bool) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(probe.trace.state, "finalize", interrupt)
    with pytest.raises(AssertionError) as caught, probe.observing(capture):
        raise primary
    assert caught.value is primary
    assert receipt.issue == Issue.OBSERVATION
    assert primary.__notes__


@pytest.mark.parametrize("permitted", [True, False])
def test_real_resource_assertion_is_preserved_with_held_linux_file(
    tmp_path: Path, request: pytest.FixtureRequest, permitted: bool
) -> None:
    # Requirement: the original resource assertion stays RED when an actual extra FD is held.
    capture = request.config.pluginmanager.getplugin("capturemanager")
    assert isinstance(capture, CaptureManager)
    receipt = Records(Budget(), Sanitizer({}))
    probe = Probe(receipt, exercise.__code__)
    control = long_process.run_control
    finalize = probe.trace.state.finalize
    raised: list[AssertionError] = []
    with ExitStack() as files, pytest.MonkeyPatch.context() as patch:

        def permission(observed: bool) -> None:
            finalize(observed and permitted)

        def retain_file(
            command: list[str], root: Path, seconds: float
        ) -> subprocess.CompletedProcess[bytes]:
            try:
                return control(command, root, seconds)
            finally:
                files.enter_context((tmp_path / "held-file").open("wb"))

        patch.setattr(long_process, "run_control", retain_file)
        patch.setattr(probe.trace.state, "finalize", permission)
        with pytest.raises(AssertionError) as caught, probe.observing(capture):
            try:
                exercise(tmp_path, patch, ActorCase("new", 0, False, False))
            except AssertionError as original:
                raised.append(original)
                raise
    assert caught.value is raised[0]
    rows = [json.loads(line.split(" ", 1)[1]) for line in receipt.lines]
    snapshots = [row for row in rows if "stage" in row]
    assert snapshots[-2]["assertion"] == "failed"
    assert snapshots[-1]["finalization"] == (
        "windows-unrun" if permitted else "unsafe-not-attempted"
    )
    assert snapshots[3]["resources"][2] == snapshots[0]["resources"][2] + 1
    assert rows[-1]["incomplete"] == ("none" if permitted else "finalization-incomplete")
