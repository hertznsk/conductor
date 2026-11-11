"""Ownership and abrupt-loss controls that run without any observer helper processes."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest
from artifact_audit import audit
from process_identity import BindingError, Identity, State
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
        observer.kill()
        observer.wait(timeout=5)
        assert audit(artifacts, tmp_path / "published") is False
        manifest = json.loads((tmp_path / "published/manifest.json").read_text())
        assert manifest["structured_artifacts_complete"] is False
        assert manifest["root_outcome"]["root_code"] is None
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
