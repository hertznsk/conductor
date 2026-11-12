"""Real Sink-open and partial-write commit barriers for the bounded startup reader."""

import json
import os
import socket
import subprocess
import threading
import time
from collections.abc import Mapping
from pathlib import Path

import psutil
import pytest
from smoke import long_ownership, long_process
from smoke.long_export import checked_control
from smoke.support import ProcessProbe, stop_owned
from smoke.test_long_ownership import command, run_fault

SCHEDULE = """
import json
import os
import socket

import psutil

from diagnostic_sink import Sink

original_init = Sink.__init__
original_write = os.write
selected = None
used = False


def barrier():
    current = psutil.Process()
    address = ('127.0.0.1', int(os.environ['QA_PORT']))
    with socket.create_connection(address, timeout=10) as conn:
        identity = {'pid': current.pid, 'created': current.create_time()}
        conn.sendall((json.dumps(identity) + '\\n').encode())
        assert conn.recv(1) == b'G'


def opened(self, path, *args, **kwargs):
    global selected
    original_init(self, path, *args, **kwargs)
    if path.parent.name == 'long-control-private' and str(path).endswith('-gw0.jsonl'):
        selected = self.fd
        if os.environ['QA_WRITE'] == 'empty':
            barrier()


def written(fd, data):
    global used
    if fd == selected and not used and os.environ['QA_WRITE'] == 'partial':
        used = True
        count = original_write(fd, data[:-1])
        barrier()
        return count
    return original_write(fd, data)


Sink.__init__ = opened
os.write = written
"""


@pytest.mark.parametrize("schedule", ["empty", "partial"])
def test_real_startup_commits_before_single_semantic_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    schedule: str,
) -> None:
    # Requirement: actual uncommitted producer bytes cannot latch a failure or grant authority.
    project = tmp_path / "project"
    project.mkdir()
    (tmp_path / "artifacts").mkdir()
    target = project / "test_probe.py"
    target.write_text(
        "import pathlib\n"
        "def test_probe():\n    pathlib.Path('body.ready').touch()\n"
        "    raise OSError(13,'password=private-body')\n"
    )
    (project / "writer_schedule.py").write_text(SCHEDULE)
    monkeypatch.setenv("PYTHONPATH", str(project) + os.pathsep + os.environ["PYTHONPATH"])
    monkeypatch.setenv("QA_WRITE", schedule)
    monkeypatch.delenv("SMOKE_EXPORT_ROOT", raising=False)
    ready = threading.Event()
    released = threading.Event()
    peers: list[ProcessProbe] = []
    direct: list[bool] = []
    children: list[subprocess.Popen[bytes]] = []
    events = []
    real_open, real_popen = Path.open, subprocess.Popen
    real_parse, real_bind = long_process.control_records, ProcessProbe.bind
    real_acquire = long_ownership.CreatorBindings.acquire

    class Stream:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def readline(self, size):
            data = self.stream.readline(size)
            events.append(["read", len(data), data.endswith(b"\n")])
            if not data.endswith(b"\n"):
                ready.set()
            return data

        def read(self, size):
            return self.stream.read(size)

    def opened(path, *args, **kwargs):
        stream = real_open(path, *args, **kwargs)
        if path.parent == tmp_path / "long-control-private" and path.name.endswith("-gw0.jsonl"):
            return Stream(stream)
        return stream

    def spawned(
        args: list[str], *, cwd: Path, env: Mapping[str, str], stdout: int
    ) -> subprocess.Popen[bytes]:
        child = real_popen(args, cwd=cwd, env=env, stdout=stdout)
        children.append(child)
        return child

    def parsed(data, sanitizer):
        result = real_parse(data, sanitizer)
        if result.startup.role == "gw0":
            events.append(["parse", len(data), data.endswith(b"\n")])
        return result

    def acquired(owner, process, created):
        if peers and process.pid == peers[0].process.pid:
            events.append(["bind", process.pid, released.is_set()])
        return real_acquire(owner, process, created)

    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(10)
        monkeypatch.setenv("QA_PORT", str(server.getsockname()[1]))

        def receiver():
            conn, _ = server.accept()
            with conn, conn.makefile("rb") as stream:
                item = json.loads(stream.readline(1024))
                process = psutil.Process(item["pid"])
                assert process.create_time() == item["created"]
                direct.append(process.ppid() == children[0].pid)
                peers.append(real_bind(process))
                assert ready.wait(10)
                released.set()
                conn.sendall(b"G")

        reader = threading.Thread(target=receiver)
        try:
            with monkeypatch.context() as patch:
                patch.setattr(Path, "open", opened)
                patch.setattr(subprocess, "Popen", spawned)
                patch.setattr(long_process, "control_records", parsed)
                patch.setattr(long_ownership.CreatorBindings, "acquire", acquired)
                reader.start()
                args = command(target) + ["-p", "writer_schedule"]
                with pytest.raises(AssertionError):
                    long_process.run_control(args, tmp_path)
            metadata = json.loads((tmp_path / "long-export/long-w1/manifest.json").read_bytes())
            view = checked_control(tmp_path / "long-export/long-w1")
            assert released.is_set() and (project / "body.ready").exists()
            assert children[0].returncode == 1 and metadata["root_code"] == 1
            assert all(c.terminal for c in view.controls)
            if direct[0] or os.name == "nt":
                assert metadata["cleanup_complete"] and metadata["complete"]
            else:
                assert not metadata["cleanup_complete"]
                assert metadata["error"] == "ownership-unavailable"
            assert len([e for e in events if e[0] == "parse"]) == 1
            assert len([e for e in events if e[0] == "bind"]) == int(direct[0] or os.name == "nt")
            assert any(e[0] == "read" and not e[2] for e in events)
            assert all(e[2] for e in events if e[0] == "bind")
            (tmp_path / "barrier-proof.json").write_text(
                json.dumps(
                    {
                        "schedule": schedule,
                        "events": events,
                        "metadata": metadata,
                        "births": [{"pid": p.process.pid, "created": p.created} for p in peers],
                    }
                )
            )
        finally:
            ready.set()
            stop_owned(
                children,
                time.monotonic() + 3,
                [p.process for p in peers] if direct and direct[0] else [],
            )
            if reader.ident is not None:
                reader.join(timeout=3)
                assert not reader.is_alive()
            for peer in peers:
                assert peer.record("closed")["status"] == "proved-exited"
                peer.close()


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        (b"{", "startup-not-bound-before-stop"),
        (b"\n", "invalid-json"),
        (b"\xff\n", "invalid-json"),
        (b"x" * 65537, "other-unsafe"),
    ],
    ids=["partial", "blank-lf", "bad-utf8", "oversize"],
)
def test_uncommitted_or_invalid_bytes_never_query_foreign_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
    reason: str,
) -> None:
    # Requirement: real partial/blank/invalid/oversize inputs fail closed without foreign authority.
    write = Path.write_bytes

    def supplied(path: Path, value: bytes) -> int:
        return write(path, payload if path.name == "0-unknown.jsonl" and not value else value)

    monkeypatch.setattr(Path, "write_bytes", supplied)
    note, events = run_fault(tmp_path, monkeypatch, "empty")
    assert f":{reason}:" in note
    assert events == []
