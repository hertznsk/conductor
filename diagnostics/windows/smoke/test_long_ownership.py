"""Actual ownership catch branches and validated worker projections, never an ownership repair."""

import json
import os
import subprocess
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace

import psutil
import pytest
from artifact_policy import Sanitizer, UnsafeArtifact
from diagnostic_sink import Sink
from smoke import long_process
from smoke.long_diagnostics import control_note
from smoke.long_export import checked_control
from smoke.long_records import control_records
from smoke.support import ProcessProbe, stop_owned


def command(target: Path) -> list[str]:
    return [
        sys.executable,
        "-m",
        "pytest",
        "-p",
        "no:cacheprovider",
        "-p",
        "pr629_diag",
        "-o",
        "faulthandler_timeout=0",
        "-q",
        str(target),
        "-n",
        "1",
        "--dist",
        "loadfile",
    ]


def run_fault(root: Path, patch: pytest.MonkeyPatch, mode: str) -> tuple[str, list[str]]:
    (root / "project").mkdir()
    (root / "artifacts").mkdir()
    target = root / "project/test_probe.py"
    target.write_text("def test_probe():\n    assert True\n")
    real_popen, real_process, real_glob = subprocess.Popen, psutil.Process, Path.glob
    real_bind, real_close = ProcessProbe.bind, ProcessProbe.close
    peer = real_popen(
        [sys.executable, "-c", "import sys;sys.stdin.buffer.read(1)"], stdin=subprocess.PIPE
    )
    peer_probe = real_bind(real_process(peer.pid))
    events: list[str] = []
    root_pid = 0

    def launch(
        args: list[str], *, cwd: Path, env: Mapping[str, str], stdout: int
    ) -> subprocess.Popen[bytes]:
        nonlocal root_pid
        path = root / "long-control-private/0-unknown.jsonl"
        if mode in ("empty", "invalid", "many"):
            path.write_bytes(b"not-json\n" if mode == "invalid" else b"")
            if mode == "many":
                for index in range(1, 4):
                    path.with_name(f"{index}-unknown.jsonl").write_bytes(b"not-json\n")
        else:
            sink = Sink(path, Sanitizer({}))
            sink.emit(
                {
                    "event": "observed",
                    "kind": "process",
                    "stage": "startup",
                    "status": "live",
                    "pid": peer.pid,
                    "parent": os.getpid(),
                    "created": peer_probe.created + (mode == "birth"),
                    "identity": peer_probe.key
                    if mode not in ("key", "close")
                    else f"{peer.pid}:altered",
                    "worker": "gw0",
                    "role": "gw0",
                    "scope": "long-control",
                }
            )
            sink.close()
        child = real_popen(args, cwd=cwd, env=env, stdout=stdout)
        root_pid = child.pid
        return child

    def ordered(path: Path, pattern: str):
        if path == root / "long-control-private" and pattern == "*.jsonl":
            first = path / "0-unknown.jsonl"
            yield first
            if mode == "many":
                yield from (path / f"{index}-unknown.jsonl" for index in range(1, 4))
            yield from (p for p in real_glob(path, pattern) if p != first)
        else:
            yield from real_glob(path, pattern)

    class Candidate:
        pid = peer.pid

        def create_time(self) -> float:
            events.append("birth")
            if mode == "subclass":
                raise type("private-subclass", (PermissionError,), {})(
                    "private-errno", "private-message"
                )
            if mode == "unsafe":
                raise UnsafeArtifact("private-reason")
            if mode == "birth-os":
                raise PermissionError(13, "password=private-query")
            return peer_probe.created

        def ppid(self) -> int:
            events.append("parent")
            actual = real_process(peer.pid).ppid()
            return root_pid if mode in ("bind", "key", "close") else actual

    def lookup(pid: int | None = None):
        if pid == peer.pid:
            events.append("lookup")
            return Candidate()
        return real_process(pid)

    def bind(process) -> ProcessProbe:
        if process.pid == peer.pid:
            events.append("bind")
            if mode == "bind":
                raise PermissionError(13, "password=private-bind")
        return real_bind(process)

    def close(probe: ProcessProbe) -> None:
        real_close(probe)
        if probe.process.pid == peer.pid and mode == "close":
            events.append("close")
            os.close(-1)

    try:
        with patch.context() as owned:
            owned.delenv("SMOKE_EXPORT_ROOT", raising=False)
            owned.setattr(subprocess, "Popen", launch)
            owned.setattr(Path, "glob", ordered)
            owned.setattr(
                long_process,
                "psutil",
                SimpleNamespace(
                    Process=lookup, NoSuchProcess=psutil.NoSuchProcess, Error=psutil.Error
                ),
            )
            owned.setattr(ProcessProbe, "bind", bind)
            owned.setattr(ProcessProbe, "close", close)
            with pytest.raises(UnsafeArtifact) as caught:
                long_process.run_control(command(target), root)
        note = control_note(caught.value)
        assert note is not None
        assert peer.poll() is None
        return note, events
    finally:
        stop_owned([peer], time.monotonic() + 3)
        if peer.stdin is not None:
            peer.stdin.close()
        assert peer_probe.record("after")["status"] == "proved-exited"
        peer_probe.close()


@pytest.mark.parametrize(
    ("mode", "stage", "reason"),
    [
        ("empty", "startup-parse", "long-startup-missing"),
        ("invalid", "startup-parse", "invalid-json"),
        ("birth", "birth-check", "ownership-mismatch"),
        ("parent", "parent-check", "ownership-mismatch"),
        ("birth-os", "birth-query", "none"),
        ("bind", "bind", "none"),
        ("key", "key-check", "ownership-mismatch"),
        ("close", "candidate-close", "none"),
        ("subclass", "birth-query", "none"),
        ("unsafe", "birth-query", "other-unsafe"),
        ("many", "startup-parse", "long-startup-missing"),
    ],
)
def test_actual_owner_branch_retains_first_fault(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    stage: str,
    reason: str,
) -> None:
    # Requirement: actual refusals retain their first discriminator without query reordering.
    note, events = run_fault(tmp_path, monkeypatch, mode)
    assert "outcome=normal:0 cleanup=false error=ownership-unavailable" in note
    assert f"owner=run:{stage}:" in note
    if mode == "birth":
        assert events == ["lookup", "birth"]
    if mode == "parent":
        assert events == ["lookup", "birth", "parent"]
    if mode == "empty":
        assert ":long-startup-missing:0:false:unknown:" in note
    if mode == "many":
        assert ":long-startup-missing:0:false:unknown:more=3" in note
    if mode == "subclass":
        assert ":unknown:unknown:unknown:none:" in note
    assert f":{reason}:" in note
    assert "private-" not in note and len(note.encode()) <= 2048


@pytest.fixture
def worker_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, str]:
    monkeypatch.delenv("SMOKE_EXPORT_ROOT", raising=False)
    (tmp_path / "project").mkdir()
    (tmp_path / "artifacts").mkdir()
    target = tmp_path / "project/test_probe.py"
    target.write_text("def test_probe():\n    raise ValueError('password=private-worker')\n")
    (tmp_path / "project/conftest.py").write_text(
        "import pytest\n@pytest.fixture(autouse=True)\n"
        "def isolated_paths():\n    from test_probe import test_probe\n    test_probe()\n"
    )
    with pytest.raises(AssertionError) as caught:
        long_process.run_control(command(target), tmp_path)
    note = control_note(caught.value)
    assert note is not None
    return tmp_path, note


def test_real_worker_setup_projects_only_first_ordinal(worker_failure: tuple[Path, str]) -> None:
    # Requirement: actual ValueError/setup retains closed nearest frames and honest config flags.
    root, note = worker_failure
    view = checked_control(root / "long-export/long-w1")
    worker = next(c for c in view.controls if c.startup.role == "gw0")
    rows = [json.loads(line) for line in worker.content.splitlines()]
    header = next(r for r in rows if r["kind"] == "exception")
    assert header["exception_type"] == "ValueError" and header["phase"] == "setup"
    assert "frames#1=" in note and "test_probe.py:test_probe:2" in note
    assert "inner-known=true" in note and "gw0.setup=absent:true" in note
    assert "private-worker" not in note and "password=" not in note


@pytest.mark.parametrize("damage", ["ordinal", "raw-name", "oversize", "large-field"])
def test_worker_reader_still_refuses_foreign_details(
    worker_failure: tuple[Path, str],
    damage: str,
) -> None:
    # Requirement: hostile frame identity or huge input cannot become a trusted note projection.
    root, _ = worker_failure
    worker = next(
        c for c in checked_control(root / "long-export/long-w1").controls if c.startup.role == "gw0"
    )
    rows = [json.loads(line) for line in worker.content.splitlines()]
    frame = next(r for r in rows if r["kind"] == "frame")
    if damage == "ordinal":
        frame["known"] = 9
    if damage == "raw-name":
        frame["path"] = "private-worker/arbitrary.py"
    if damage == "large-field":
        frame["path"] = "x" * 70000
    content = (
        b"x" * 65537
        if damage == "oversize"
        else ("".join(json.dumps(r) + "\n" for r in rows).encode())
    )
    with pytest.raises(UnsafeArtifact):
        control_records(content, Sanitizer({}))
