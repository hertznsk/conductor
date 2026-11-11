"""Ownership and abrupt-loss controls that run without any observer helper processes."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

import psutil
import pytest
from artifact_audit import audit
from artifact_policy import Record, Sanitizer
from diagnostic_sink import Sink
from process_identity import BindingError, Identity, State
from process_samples import Ledger
from supervisor import Budget, supervise
from support import read_records, stop_owned, wait_until
from windows_identity import WindowsIdentity


def test_exited_child_before_first_reap_has_stable_identity() -> None:
    # Requirement: physical exit before binding never permits replacement PID adoption.
    child = subprocess.Popen([sys.executable, "-c", "raise SystemExit(7)"])
    try:
        if sys.platform == "win32":
            native = WindowsIdentity.child(child)
            wait_until(native.exited, time.monotonic() + 5)
        else:
            process = psutil.Process(child.pid)
            wait_until(lambda: process.status() == psutil.STATUS_ZOMBIE, time.monotonic() + 5)
        assert child.returncode is None
        identity = Identity.child(child)
        assert identity.pid == child.pid
        assert identity.observe() == State.EXITED
        assert child.wait(timeout=5) == 7
        identity.close()
        if sys.platform != "win32":
            with pytest.raises(BindingError) as refused:
                Identity.child(child)
            assert refused.value.state == State.AMBIGUOUS
    finally:
        stop_owned([child], time.monotonic() + 5)


def test_wrong_lookup_does_not_adopt_sibling(monkeypatch: pytest.MonkeyPatch) -> None:
    # Requirement: wrong lookup fails POSIX binding and cannot replace a Windows child handle.
    child = subprocess.Popen([sys.executable, "-c", "import threading;threading.Event().wait(10)"])
    sibling = subprocess.Popen(
        [sys.executable, "-c", "import threading;threading.Event().wait(10)"]
    )
    foreign = psutil.Process(sibling.pid)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(psutil, "Process", lambda pid=None: foreign)
            if sys.platform == "win32":
                identity = Identity.child(child)
                assert identity.pid == child.pid
                identity.close()
            else:
                with pytest.raises(BindingError) as refused:
                    Identity.child(child)
                assert refused.value.state == State.MISMATCH
        assert sibling.poll() is None
    finally:
        stop_owned([child, sibling], time.monotonic() + 5)


def test_abrupt_observer_loss_is_incomplete_evidence(tmp_path: Path) -> None:
    # Requirement: a killed observer cannot manufacture a successful target or evidence outcome.
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    command = tmp_path / "command.json"
    command.write_text(
        json.dumps([sys.executable, "-c", "import threading;threading.Event().wait(15)"])
    )
    driver = Path(__file__).with_name("driver.py")
    observer = subprocess.Popen([sys.executable, str(driver), str(artifacts), str(command)])
    root: psutil.Process | None = None
    try:
        wait_until(
            lambda: any(
                record["event"] == "binding"
                for record in read_records(artifacts / "supervisor.jsonl")
            ),
            time.monotonic() + 5,
        )
        binding = next(
            record
            for record in read_records(artifacts / "supervisor.jsonl")
            if record["event"] == "binding"
        )
        root_pid = binding["pid"]
        assert isinstance(root_pid, int)
        root = psutil.Process(root_pid)
        wait_until(
            lambda: sum(r["event"] == "host" for r in read_records(artifacts / "processes.jsonl"))
            >= 2,
            time.monotonic() + 14,
        )
        observer.kill()
        observer.wait(timeout=5)
        assert audit(artifacts, tmp_path / "published") is False
        manifest = json.loads((tmp_path / "published/manifest.json").read_text())
        assert manifest["structured_artifacts_complete"] is False
        assert manifest["root_outcome"]["root_code"] is None
        resource = json.loads((tmp_path / "published/resource-summary.json").read_text())
        assert resource["right_censored"] and resource["records_consumed"] >= 2
        assert resource["measurements"]["host"]["intervals"] >= 1
    finally:
        stop_owned([observer], time.monotonic() + 15, [] if root is None else [root])


def test_actual_closed_fd_two_cannot_escape_sink_failure(tmp_path: Path) -> None:
    # Requirement: both the primary fd and native stderr can be closed without changing caller code.
    code = (
        "import os,sys;from artifact_policy import Sanitizer;from diagnostic_sink import Sink;"
        "from pathlib import Path;"
        "sink=Sink(Path(sys.argv[1]),Sanitizer({}));"
        "os.close(sink.fd);os.close(2);"
        "ok=sink.emit({'event':'collected','nodeid':'x'});"
        "sys.exit(9 if ok else 0)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code, str(tmp_path / "record.jsonl")], timeout=5, check=False
    )
    assert result.returncode == 0
    assert (tmp_path / "record.failure").exists()


def test_exited_close_error_is_recorded_without_observation_latch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Requirement: a failed close after proven exit preserves lifecycle and supplies safe evidence.
    child = subprocess.Popen([sys.executable, "-c", "raise SystemExit(7)"])
    sink = Sink(tmp_path / "supervisor.jsonl", Sanitizer({}))
    try:
        identity = Identity.child(child)
        assert child.wait(timeout=5) == 7
        assert identity.observe() == State.EXITED

        def refuse_close(item: Identity) -> None:
            raise PermissionError(13, "token=private-close-payload")

        monkeypatch.setattr(Identity, "close", refuse_close)
        ledger = Ledger(identity, sink)
        assert ledger.finish(sink)
        assert not ledger.failed
        errors = [r for r in read_records(sink.path) if r["event"] == "process.close_error"]
        assert len(errors) == 1
        assert errors[0]["identity"] == identity.key
        assert errors[0]["status"] == "proved-exited"
        assert errors[0]["reason"] == "process-handle-close-failed"
        assert "private-close-payload" not in sink.path.read_text()
        ledger.observe(sink)
        assert ledger.finish(sink) and ledger.close_errors_count == 1
    finally:
        sink.close()
        stop_owned([child], time.monotonic() + 5)


@pytest.mark.parametrize("stage", ["live-close", "duplicate", "discovery", "query"])
def test_close_or_query_gap_cannot_become_cleanup_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    # Requirement: live/unbound close, discovery and numeric failures keep a monotone reason latch.
    child = subprocess.Popen(
        [sys.executable, "-c", "import sys;sys.stdin.buffer.read(1)"], stdin=subprocess.PIPE
    )
    sink = Sink(tmp_path / "supervisor.jsonl", Sanitizer({}))
    samples = Sink(tmp_path / "processes.jsonl", Sanitizer({}))
    try:
        root = Identity.child(child)
        ledger = Ledger(root, sink)

        def refuse_close(item: Identity) -> None:
            raise OSError(5, "secret=private-query-payload")

        match stage:
            case "live-close":
                monkeypatch.setattr(Identity, "close", refuse_close)
                ledger.close(root, "finish")
            case "duplicate":
                monkeypatch.setattr(Identity, "close", refuse_close)
                duplicate = Identity(
                    root.pid,
                    root.created,
                    role="unknown",
                    state=State.EXITED,
                    first_exit=time.monotonic(),
                )
                ledger.close(duplicate, "discover-duplicate")
            case "discovery":
                monkeypatch.setattr(
                    Identity,
                    "descendant",
                    lambda *args: (_ for _ in ()).throw(OSError(5, "private")),
                )
                process = psutil.Process()
                monkeypatch.setattr(psutil, "process_iter", lambda *args: [process])
                # The injected process advertises the bound parent through psutil's info boundary.
                monkeypatch.setattr(process, "info", {"ppid": root.pid}, raising=False)
                ledger.discover()
            case "query":
                monkeypatch.setattr(
                    psutil.Process,
                    "memory_info",
                    lambda *args: (_ for _ in ()).throw(psutil.AccessDenied(child.pid)),
                )
                ledger.sample(samples)
        assert ledger.failed
        reasons = [r for r in read_records(sink.path) if r["event"] == "observer.error"]
        assert reasons and all(r.get("stage") and "reason" in r for r in reasons)
        assert "private" not in sink.path.read_text()
        assert child.stdin is not None
        child.stdin.close()
        assert child.wait(timeout=5) == 0
        root.state, root.first_exit = State.EXITED, time.monotonic()
        ledger.finish(samples)
        assert ledger.failed
    finally:
        sink.close()
        samples.close()
        stop_owned([child], time.monotonic() + 5)


def test_close_error_detail_cap_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Requirement: overflow counts every failed ownership object but cannot claim complete evidence.
    sink = Sink(tmp_path / "supervisor.jsonl", Sanitizer({}))
    root = Identity(1, 1.0, state=State.EXITED, first_exit=1.0)
    ledger = Ledger(root, sink)
    for pid in range(2, 258):
        item = Identity(pid, 1.0, state=State.EXITED, first_exit=1.0)
        ledger.known[item.key] = item

    def refused(item: Identity) -> None:
        raise PermissionError(13, "private")

    monkeypatch.setattr(Identity, "close", refused)
    try:
        assert ledger.finish(sink)
        assert ledger.close_errors_count == 257 and ledger.close_errors_recorded == 256
        assert ledger.cleanup()["close_error_evidence_complete"] is False
        assert sink.failure == "close-error-evidence-incomplete"
    finally:
        sink.close()


def test_role_parse_failure_has_bounded_reason(
    tmp_path: Path,
) -> None:
    # Requirement: every fatal role receipt failure has a reason instead of an unexplained latch.
    child = subprocess.Popen([sys.executable, "-c", "raise SystemExit(0)"])
    sink = Sink(tmp_path / "supervisor.jsonl", Sanitizer({}))
    try:
        identity = Identity.child(child)
        ledger = Ledger(identity, sink)
        (tmp_path / "1-controller.phase.jsonl").write_bytes(b"bad\n")
        ledger.roles(tmp_path)
        assert ledger.failed
        assert any(r["event"] == "observer.error" for r in read_records(sink.path))
    finally:
        sink.close()
        stop_owned([child], time.monotonic() + 5)


@pytest.mark.parametrize("code", [0, 1, 7])
@pytest.mark.parametrize("failure", ["overflow", "zero", "partial"])
def test_supervisor_close_failure_preserves_audited_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    code: int,
    failure: str,
) -> None:
    # Requirement: close-detail overflow/write refusal loses evidence, never a known child outcome.
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    finish = Ledger.finish
    emit = Sink.emit
    original_write = os.write
    attempts = 0

    def broken_write(fd: int, payload: bytes) -> int:
        nonlocal attempts
        attempts += 1
        if failure == "zero":
            return 0
        if attempts == 1:
            return original_write(fd, payload[:3])
        raise OSError("controlled-close-record-write-refusal")

    def close_record(sink: Sink, record: Record) -> bool:
        if record["event"] == "process.close_error" and failure != "overflow":

            def only_primary(fd: int, payload: bytes) -> int:
                return broken_write(fd, payload) if fd == sink.fd else original_write(fd, payload)

            with patch("diagnostic_sink.os.write", only_primary):
                return emit(sink, record)
        return emit(sink, record)

    def refused_finish(ledger: Ledger, sink: Sink) -> bool:
        if failure == "overflow":
            for pid in range(10_000_000, 10_000_256):
                item = Identity(pid, 1.0, state=State.EXITED, first_exit=time.monotonic())
                ledger.known[item.key] = item
        with patch.object(Identity, "close", side_effect=PermissionError(13, "private")):
            return finish(ledger, sink)

    monkeypatch.setattr(Ledger, "finish", refused_finish)
    monkeypatch.setattr(Sink, "emit", close_record)
    actual = supervise(
        [sys.executable, "-c", f"raise SystemExit({code})"],
        artifacts,
        Budget(time.monotonic(), seconds=15, grace=0),
    )
    assert actual == code
    post = read_records(artifacts / "post-root.jsonl")
    assert post[-1]["root_code"] == code
    assert post[-1]["close_error_evidence_complete"] is False
    assert post[-1]["close_errors_count"] == (257 if failure == "overflow" else 1)
    assert post[-1]["close_errors_recorded"] == (256 if failure == "overflow" else 0)
    assert not any(r["event"] == "exit" for r in read_records(artifacts / "supervisor.jsonl"))
    staging = tmp_path / "published"
    output = tmp_path / "output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    assert not audit(artifacts, staging)
    manifest = json.loads((staging / "manifest.json").read_text())
    assert manifest["root_outcome"]["root_code"] == code
    assert manifest["root_outcome"]["outcome_status"] == "recovered"
    assert manifest["root_outcome"]["outcome_sources"]
    assert manifest["structured_artifacts_complete"] is False
    assert str(staging / "manifest.json") in output.read_text()
    if failure == "partial":
        entry = next(r for r in manifest["artifacts"] if r["path"] == "supervisor.jsonl")
        assert entry["status"] == "withheld" and entry["reason"] == "partial-jsonl-tail"
    for r in post:
        created, pid = r.get("created"), r.get("pid")
        if isinstance(created, (int, float)) and created > 1_000_000_000:
            assert isinstance(pid, int)
            assert not psutil.pid_exists(pid)
