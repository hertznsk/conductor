"""Real process controls for inherited output and frozen post-root observation."""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest
from artifact_audit import audit
from support import read_records, stop_owned, wait_until

DRIVER = Path(__file__).with_name("driver.py")
SPECIMEN = Path(__file__).with_name("specimen.py")


@pytest.mark.parametrize(
    ("code", "fault"),
    [
        (0, ""),
        (1, ""),
        (7, ""),
        (7, "binding"),
        (7, "nosuch"),
        (7, "denied"),
        (7, "final"),
    ],
)
def test_immediate_exit_preserved_on_binding_fault(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    code: int,
    fault: str,
) -> None:
    # Requirement: a real short-lived child retains its code even when the observer cannot bind.
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    command = tmp_path / "command.json"
    command.write_text(json.dumps([sys.executable, "-c", f"raise SystemExit({code})"]))
    if fault:
        monkeypatch.setenv("SMOKE_BINDING_FAULT", fault)
    result = subprocess.run(
        [sys.executable, str(DRIVER), str(artifacts), str(command)], timeout=10, check=False
    )
    assert result.returncode == code
    records = read_records(artifacts / "supervisor.jsonl")
    assert records[-1]["root_code"] == code
    assert records[-1]["observer_failed"] is bool(fault)
    if fault:
        assert any(record["event"] == "observer.error" for record in records)


@pytest.mark.parametrize("fault", ["binding", "final"])
def test_audit_preserves_root_code_after_observer_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    # Requirement: failed evidence retains the real child outcome through the final manifest.
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    command = tmp_path / "command.json"
    command.write_text(json.dumps([sys.executable, "-c", "raise SystemExit(7)"]))
    monkeypatch.setenv("SMOKE_BINDING_FAULT", fault)
    result = subprocess.run(
        [sys.executable, str(DRIVER), str(artifacts), str(command)], timeout=10, check=False
    )
    assert result.returncode == 7
    records = read_records(artifacts / "supervisor.jsonl")
    assert any(record["event"] == "observer.error" for record in records)
    assert records[-1]["root_code"] == 7 and records[-1]["observer_failed"] is True

    staging = tmp_path / "refused"
    assert audit(artifacts, staging) is False
    manifest = json.loads((staging / "manifest.json").read_text())
    assert manifest["structured_artifacts_complete"] is False
    supervisor = next(item for item in manifest["artifacts"] if item["path"] == "supervisor.jsonl")
    assert supervisor["status"] == "withheld" and supervisor["reason"] == "producer-incomplete"
    assert manifest["root_outcome"]["root_code"] == 7
    assert manifest["root_outcome"]["observer_failed"] is True


@pytest.mark.parametrize("mode", ["natural", "live", "interrupted"])
def test_known_child_outlives_root_without_eof_wait(tmp_path: Path, mode: str) -> None:
    # Requirement: freeze identities, preserve code 7, bound grace and leave the sibling alive.
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    command = tmp_path / "command.json"
    command.write_text(
        json.dumps([sys.executable, str(SPECIMEN.with_name("peer.py")), str(tmp_path), "parent"])
    )
    foreign = subprocess.Popen(
        [sys.executable, "-c", "import threading;threading.Event().wait(15)"]
    )
    observer = subprocess.Popen(
        [sys.executable, str(DRIVER), str(artifacts), str(command)],
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
    )
    connection: socket.socket | None = None
    peer: psutil.Process | None = None
    try:
        deadline = time.monotonic() + 8
        wait_until(lambda: (tmp_path / "child.ready").exists(), deadline)
        info = json.loads((tmp_path / "child.ready").read_text())
        peer = psutil.Process(info["pid"])
        assert peer.create_time() == info["created"]
        peer_pid = peer.pid
        connection = socket.create_connection(("127.0.0.1", info["port"]), timeout=3)
        wait_until(
            lambda: any(
                record.get("pid") == peer_pid
                for record in read_records(artifacts / "processes.jsonl")
            ),
            deadline,
        )
        (tmp_path / "root.release").touch()
        wait_until(
            lambda: any(
                record["event"] == "root-exit"
                for record in read_records(artifacts / "supervisor.jsonl")
            ),
            deadline,
        )
        if mode == "natural":
            connection.sendall(b"x")
        if mode == "interrupted":
            observer.send_signal(
                signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGTERM
            )
        assert observer.wait(timeout=3) == 7
        post = read_records(artifacts / "post-root.jsonl")
        identities = {
            record["identity"]: record for record in post if record["event"] == "observed"
        }
        child = next(record for record in identities.values() if record["pid"] == peer.pid)
        if mode == "interrupted":
            assert post[-1]["interrupted"] is True
        else:
            assert child["status"] == ("proved-exited" if mode == "natural" else "live")
        assert child["parent_identity"] in identities
        assert identities[child["parent_identity"]]["status"] == "proved-exited"
        if mode != "interrupted":
            assert post[-1]["complete"] is (mode == "natural")
        assert all(record["pid"] != foreign.pid for record in identities.values())
        assert foreign.poll() is None
    finally:
        if connection is not None:
            # EOF releases this QA-owned peer even after an earlier assertion failed.
            connection.close()
        stop_owned([observer, foreign], time.monotonic() + 15, [] if peer is None else [peer])


def test_watchdog_survives_unconfigure_and_closed_stderr(tmp_path: Path) -> None:
    # Requirement: the actual 60-second watchdog writes into the private fd after pytest cleanup.
    program = (
        "import os,sys,threading,pytest;"
        "code=pytest.main(['-p','no:cacheprovider','-p','pr629_diag',"
        "'-o','faulthandler_timeout=0',sys.argv[1]]);"
        "os.close(2);threading.Event().wait(62);sys.exit(code)"
    )
    environment = {**os.environ, "PR629_DIAG_DIR": str(tmp_path), "DIAG_SMOKE_FAIL": "0"}
    result = subprocess.run(
        [sys.executable, "-c", program, str(SPECIMEN)], env=environment, timeout=75, check=False
    )
    assert result.returncode == 0
    stack = next((tmp_path / "private").glob("*.stack.txt")).read_text()
    assert "Timeout (0:01:00)!" in stack and "threading.py" in stack
    assert any(
        record["event"] == "unconfigure.end"
        for record in read_records(next(tmp_path.glob("*.phase.jsonl")))
    )


@pytest.mark.parametrize("failure", ["setup", "rearm"])
def test_plugin_failure_does_not_change_pytest_result(tmp_path: Path, failure: str) -> None:
    # Requirement: sink and watchdog failures do not change a passing pytest outcome.
    directory = tmp_path / "records"
    if failure == "setup":
        directory.write_text("not a directory")
    else:
        directory.mkdir()
    program = (
        "import faulthandler,pytest,sys;"
        + (
            "faulthandler.dump_traceback_later=lambda *a,**k:(_ for _ in ()).throw(OSError());"
            if failure == "rearm"
            else ""
        )
        + "sys.exit(pytest.main(['-p','no:cacheprovider','-p','pr629_diag',sys.argv[1]]))"
    )
    result = subprocess.run(
        [sys.executable, "-c", program, str(SPECIMEN)],
        env={**os.environ, "PR629_DIAG_DIR": str(directory)},
        timeout=10,
        check=False,
    )
    assert result.returncode == 0


@pytest.mark.parametrize("recipient", ["root", "observer"])
def test_real_signal_keeps_root_outcome_distinct(tmp_path: Path, recipient: str) -> None:
    # Requirement: cancellation is observed separately from a known physical child return code.
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    command = tmp_path / "command.json"
    program = "import signal,threading,pathlib,sys;"
    if sys.platform == "win32":
        program += "signal.signal(signal.SIGBREAK,signal.SIG_IGN);"
    program += "pathlib.Path(sys.argv[1]).touch();threading.Event().wait(15)"
    ready = tmp_path / "signal.ready"
    command.write_text(json.dumps([sys.executable, "-c", program, str(ready)]))
    observer = subprocess.Popen(
        [sys.executable, str(DRIVER), str(artifacts), str(command)],
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
    )
    root: psutil.Process | None = None
    try:
        wait_until(
            lambda: any(
                record["event"] == "binding"
                for record in read_records(artifacts / "supervisor.jsonl")
            ),
            time.monotonic() + 5,
        )
        record = next(
            record
            for record in read_records(artifacts / "supervisor.jsonl")
            if record["event"] == "binding"
        )
        root_pid = record["pid"]
        assert isinstance(root_pid, int)
        root = psutil.Process(root_pid)
        wait_until(ready.exists, time.monotonic() + 5)
        if recipient == "root":
            root.terminate()
        else:
            observer.send_signal(
                signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGTERM
            )
        observer.wait(timeout=5)
        result = read_records(artifacts / "supervisor.jsonl")[-1]
        if recipient == "root":
            assert result["root_code"] is not None and result["root_code"] != 0
        else:
            assert result["root_code"] is None and result["interrupted"] is True
    finally:
        stop_owned([observer], time.monotonic() + 15, [] if root is None else [root])
