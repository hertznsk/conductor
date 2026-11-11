"""Mandatory hosted Windows controls. This file is not selected by the local Linux smoke."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

import psutil
import pytest
from artifact_audit import audit
from artifact_policy import Sanitizer
from diagnostic_sink import Sink
from process_identity import Identity, State
from process_samples import Ledger
from smoke.support import read_records, stop_owned, wait_until
from windows_identity import WindowsIdentity, kernel_api, popen_handle


@pytest.mark.parametrize("code", [0, 1, 259])
def test_actual_popen_handle_survives_immediate_exit(code: int) -> None:
    # Requirement: raw FILETIME/PID and signaled HANDLE prove exit, including status 259.
    assert sys.platform == "win32"
    assert sys.implementation.name == "cpython" and sys.version_info[:2] == (3, 13)
    child = subprocess.Popen([sys.executable, "-c", f"raise SystemExit({code})"])
    try:
        assert child.wait(timeout=5) == code
        identity = Identity.child(child)
        created, exited, kernel, user = (wintypes.FILETIME() for _ in range(4))
        api = kernel_api()
        assert api.GetProcessTimes(
            popen_handle(child),
            ctypes.byref(created),
            ctypes.byref(exited),
            ctypes.byref(kernel),
            ctypes.byref(user),
        )
        assert identity.native is not None
        assert identity.native.ticks == (created.dwHighDateTime << 32) | created.dwLowDateTime
        assert identity.pid == api.GetProcessId(popen_handle(child))
        assert identity.observe() == State.EXITED
        identity.close()
        assert api.GetProcessId(popen_handle(child)) == child.pid
    finally:
        stop_owned([child], time.monotonic() + 5)


def test_wrong_pid_lookup_cannot_adopt_foreign_process(monkeypatch: pytest.MonkeyPatch) -> None:
    # Requirement: a wrong PID lookup cannot replace the actual child handle.
    assert sys.platform == "win32"
    child = subprocess.Popen([sys.executable, "-c", "raise SystemExit(7)"])
    foreign = subprocess.Popen(
        [sys.executable, "-c", "import threading;threading.Event().wait(15)"]
    )
    try:
        assert child.wait(timeout=5) == 7
        unrelated = psutil.Process(foreign.pid)
        monkeypatch.setattr(psutil, "Process", lambda pid=None: unrelated)
        identity = Identity.child(child)
        assert identity.pid == child.pid and identity.pid != foreign.pid
        assert identity.observe() == State.EXITED
        assert foreign.poll() is None
        identity.close()
    finally:
        stop_owned([child, foreign], time.monotonic() + 5)


def test_native_query_failure_preserves_real_child_code(tmp_path: Path) -> None:
    # Requirement: GetProcessTimes failure is diagnostic failure, not a substituted target result.
    assert sys.platform == "win32"
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    command = tmp_path / "command.json"
    command.write_text(json.dumps([sys.executable, "-c", "raise SystemExit(7)"]))
    driver = Path(__file__).parents[1] / "smoke/driver.py"
    result = subprocess.run(
        [sys.executable, str(driver), str(artifacts), str(command)],
        env={**os.environ, "SMOKE_BINDING_FAULT": "native"},
        timeout=10,
        check=False,
    )
    records = read_records(artifacts / "supervisor.jsonl")
    assert result.returncode == 7
    assert records[-1]["root_code"] == 7 and records[-1]["observer_failed"] is True
    staging = tmp_path / "refused"
    assert audit(artifacts, staging) is False
    manifest = json.loads((staging / "manifest.json").read_text())
    assert manifest["structured_artifacts_complete"] is False
    assert manifest["root_outcome"]["root_code"] == 7
    assert manifest["root_outcome"]["observer_failed"] is True


def test_console_break_is_observer_interruption(tmp_path: Path) -> None:
    # Requirement: a control event targets only the QA group and preserves unknown outcome.
    assert sys.platform == "win32"
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    command = tmp_path / "command.json"
    command.write_text(
        json.dumps(
            [
                sys.executable,
                "-c",
                "import signal,threading,pathlib,sys;signal.signal(signal.SIGBREAK,signal.SIG_IGN);"
                "pathlib.Path(sys.argv[1]).touch();threading.Event().wait(15)",
                str(tmp_path / "ready"),
            ]
        )
    )
    driver = Path(__file__).parents[1] / "smoke/driver.py"
    observer = subprocess.Popen(
        [sys.executable, str(driver), str(artifacts), str(command)],
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )
    native: WindowsIdentity | None = None
    try:
        wait_until(
            lambda: any(
                r["event"] == "binding" for r in read_records(artifacts / "supervisor.jsonl")
            ),
            time.monotonic() + 5,
        )
        record = next(
            r for r in read_records(artifacts / "supervisor.jsonl") if r["event"] == "binding"
        )
        root_pid = record["pid"]
        assert isinstance(root_pid, int)
        native = WindowsIdentity.descendant(root_pid)
        wait_until((tmp_path / "ready").exists, time.monotonic() + 5)
        observer.send_signal(signal.CTRL_BREAK_EVENT)
        assert observer.wait(timeout=5) == 130
        outcome = read_records(artifacts / "supervisor.jsonl")[-1]
        assert outcome["interrupted"] is True
        assert outcome["root_code"] is None
        assert not native.exited()
    finally:
        stop_owned([observer], time.monotonic() + 5)
        if native is not None:
            if not native.exited():
                psutil.Process(native.pid).terminate()
            wait_until(native.exited, time.monotonic() + 5)
            native.close()


def test_stdout_stderr_inherit_actions_handles(capfd: pytest.CaptureFixture[str]) -> None:
    # Requirement: hosted log receives fixed markers; the service creates no output reader/files.
    assert sys.platform == "win32"
    with capfd.disabled():
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import sys;print('R3_STDOUT_INHERITED',flush=True);"
                "print('R3_STDERR_INHERITED',file=sys.stderr,flush=True)",
            ],
            stdout=None,
            stderr=None,
        )
        try:
            assert child.stdout is None and child.stderr is None
            assert child.wait(timeout=5) == 0
        finally:
            stop_owned([child], time.monotonic() + 5)


def test_setup_receipt_matches_real_source_checkout_and_service() -> None:
    # Requirement: hosted provenance proves the actual S/D checkout and lock hash.
    assert sys.platform == "win32"
    root = Path(os.environ["RUNNER_TEMP"]) / "windows-preflight-diagnostic"
    checkout = Path(os.environ["GITHUB_WORKSPACE"])
    records = read_records(root / "artifacts/environment.jsonl")
    environment = next(record for record in records if record["event"] == "environment")
    expected_service = os.environ["GITHUB_SHA"]
    for field, revision in (("sha", "HEAD"), ("tree", "HEAD^{tree}")):
        actual = subprocess.check_output(
            ["git", "rev-parse", revision],
            cwd=checkout,
            env={**os.environ, "GIT_MASTER": "1"},
            text=True,
            timeout=10,
        ).strip()
        assert environment[field] == actual
    assert environment["scope"] == "published-source"
    assert environment["service_sha"] == expected_service
    assert (
        environment["lock_hash"] == hashlib.sha256((checkout / "uv.lock").read_bytes()).hexdigest()
    )
    assert {"github-copilot-sdk", "claude-agent-sdk"}.issubset(
        {
            package
            for record in records
            if record["event"] == "version" and isinstance(package := record.get("package"), str)
        }
    )


def test_owned_close_is_idempotent_and_borrowed_root_stays_usable() -> None:
    # Requirement: only owned handles close, once; the Popen borrowed handle stays usable.
    assert sys.platform == "win32"
    child = subprocess.Popen(
        [sys.executable, "-c", "import sys;sys.stdin.buffer.read(1)"], stdin=subprocess.PIPE
    )
    owned = WindowsIdentity.descendant(child.pid)
    borrowed = WindowsIdentity.child(child)
    try:
        assert child.stdin is not None
        child.stdin.close()
        assert child.wait(timeout=5) == 0
        assert owned.exited()
        owned.close()
        assert owned.closed and owned.close_error is None
        owned.close()
        borrowed.close()
        assert not borrowed.closed and borrowed.kernel.GetProcessId(borrowed.handle) == child.pid
    finally:
        owned.close()
        stop_owned([child], time.monotonic() + 5)


def test_protected_exited_handle_has_terminal_failed_close(tmp_path: Path) -> None:
    # Requirement: real PROTECT_FROM_CLOSE refusal preserves exit and never retries a handle value.
    assert sys.platform == "win32"
    child = subprocess.Popen(
        [sys.executable, "-c", "import sys;sys.stdin.buffer.read(1)"], stdin=subprocess.PIPE
    )
    native = WindowsIdentity.descendant(child.pid)
    identity = Identity(child.pid, psutil.Process(child.pid).create_time(), native, role="gw0")
    sink = Sink(tmp_path / "supervisor.jsonl", Sanitizer({}))
    api = native.kernel
    api.SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
    api.SetHandleInformation.restype = wintypes.BOOL
    try:
        assert child.stdin is not None
        child.stdin.close()
        assert child.wait(timeout=5) == 0
        assert identity.observe() == State.EXITED
        assert api.SetHandleInformation(native.handle, 2, 2)
        ledger = Ledger(identity, sink)
        ledger.observe(sink)
        assert not ledger.failed and not native.closed
        failure = native.close_error
        assert failure is not None and failure.winerror is not None
        # Remove protection before the repeated call: retrying now would incorrectly succeed.
        assert api.SetHandleInformation(native.handle, 2, 0)
        with pytest.raises(OSError) as caught:
            native.close()
        assert caught.value is failure and not native.closed
        assert ledger.finish(sink) and ledger.close_errors_count == 1
        assert ledger.cleanup()["observer_cleanup_status"] == "close-error"
        errors = [r for r in read_records(sink.path) if r["event"] == "process.close_error"]
        assert len(errors) == 1 and errors[0]["first_exit"] == identity.first_exit
        assert errors[0]["winerror"] == failure.winerror
    finally:
        try:
            assert api.SetHandleInformation(native.handle, 2, 0)
            assert api.CloseHandle(native.handle)
        finally:
            sink.close()
            stop_owned([child], time.monotonic() + 5)
