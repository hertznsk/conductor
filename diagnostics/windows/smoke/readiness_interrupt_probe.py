"""Test-only finite actors and actual signal barriers for optional final observation."""

import json
import os
import signal
import socket
import subprocess
import sys
import time
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import psutil
from artifact_policy import Sanitizer, UnsafeArtifact
from diagnostic_sink import Sink
from smoke import long_process as source
from smoke.long_diagnostics import control_note
from smoke.support import ProcessProbe


def actor(root: Path, role: str) -> None:
    """Keep the worker alive only while its real parent holds the input pipe."""
    if role == "worker":
        probe = ProcessProbe.bind(psutil.Process())
        try:
            with_sink = Sink(root / "startup.jsonl", Sanitizer({}))
            with_sink.emit(
                {
                    "event": "observed",
                    "kind": "process",
                    "stage": "startup",
                    "status": "live",
                    "pid": os.getpid(),
                    "parent": os.getppid(),
                    "created": probe.created,
                    "identity": probe.key,
                    "worker": "gw0",
                    "role": "gw0",
                    "scope": "long-control",
                }
            )
            with_sink.close()
            with socket.create_connection(
                ("127.0.0.1", int(os.environ["QA_PEER_PORT"])), timeout=10
            ) as conn:
                conn.sendall(
                    (json.dumps({"pid": os.getpid(), "created": probe.created}) + "\n").encode()
                )
            sys.stdin.buffer.read(1)
            (root / "worker.eof").touch()
        finally:
            probe.close()
    else:
        with subprocess.Popen(
            [sys.executable, "-m", "smoke.readiness_interrupt_probe", str(root), "worker"],
            stdin=subprocess.PIPE,
        ) as peer:
            assert peer.stdin is not None
            sys.stdin.buffer.read(1)
            peer.stdin.close()
            peer.wait(timeout=10)
        sys.exit(int(os.environ["QA_EXIT"]))


def controller(root: Path, mode: str) -> None:
    """Record source effects before the owning test's separate rescue safety net."""
    (root / "project").mkdir()
    os.environ.pop("SMOKE_EXPORT_ROOT", None)
    os.environ["PYTHONPATH"] = os.pathsep.join(sys.path)
    os.environ["QA_EXIT"] = "1" if mode == "normal1" else "0"
    repeated = mode in ("repeat", "bound", "repeat-publication")
    if mode.endswith("publication"):
        (root / "long-export").mkdir()
        (root / "long-export/long-w1").write_bytes(b"blocked")
    roots, held, owners, closes, stops, reads, barriers = [], [], [], [], [], [], []
    first = secondary = active = caught = root_birth = None
    pending = root / "long-control-private/0-pending.jsonl"
    real_spawn, real_open = subprocess.Popen, Path.open
    real_bind, real_close, real_stop = ProcessProbe.bind, ProcessProbe.close, source.stop_owned
    real_init = source.CreatorBindings.__init__

    def snapshot():
        try:
            peer_state = held[0].process.status()
        except psutil.NoSuchProcess:
            peer_state = "absent"
        return {
            "root_live": roots[0].poll() is None,
            "root_code": roots[0].returncode,
            "peer": held[0].record("before-rescue")["status"],
            "peer_os_state": peer_state,
            "grants": {n.probe.process.pid: n.kind for o in owners for n in o.nodes.values()},
            "closes": closes.copy(),
            "stops": stops.copy(),
            "eof": (root / "worker.eof").exists(),
        }

    def interrupt(stage):
        if roots[0].poll() is not None:
            held[0].process.wait(timeout=2)
        event = {"stage": stage, **snapshot()}
        barriers.append(event)
        with socket.create_connection(
            ("127.0.0.1", int(os.environ["QA_SIGNAL_PORT"])), timeout=10
        ) as conn:
            conn.sendall((json.dumps(event) + "\n").encode())
            command = conn.recv(1)
            if command == b"S":
                signal.raise_signal(signal.SIGINT)
        raise AssertionError("Owned sender did not deliver its requested interrupt")

    with socket.socket() as server, ExitStack() as edits:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(10)
        os.environ["QA_PEER_PORT"] = str(server.getsockname()[1])

        def launch(args, *, cwd, env, stdout):
            nonlocal root_birth
            # Use the actual runtime binary and import path, avoiding a launcher alias.
            child = real_spawn(
                [
                    psutil.Process().exe(),
                    "-m",
                    "smoke.readiness_interrupt_probe",
                    str(root),
                    "root",
                ],
                cwd=cwd,
                env=env,
                stdout=stdout,
                stdin=subprocess.PIPE,
            )
            roots.append(child)
            root_birth = psutil.Process(child.pid).create_time()
            assert child.stdin is not None
            with server.accept()[0] as conn, conn.makefile("rb") as stream:
                item = json.loads(stream.readline(1024))
            process = psutil.Process(item["pid"])
            assert process.create_time() == item["created"] and process.ppid() == child.pid
            held.append(real_bind(process))
            pending.write_bytes(b"")
            if mode == "bound":
                (pending.parent / f"{process.pid}-gw0.jsonl").write_bytes(
                    (root / "startup.jsonl").read_bytes()
                )
            waited = child.wait
            released = False

            def wait(timeout: float | None = None) -> int:
                nonlocal first, released
                assert child.stdin is not None
                if not repeated and mode != "timeout" and not released:
                    released = True
                    child.stdin.write(b"G")
                    child.stdin.flush()
                try:
                    return waited(timeout=timeout)
                except subprocess.TimeoutExpired:
                    if repeated and first is None:
                        try:
                            interrupt("wait-timeout")
                        except KeyboardInterrupt as error:
                            first = error
                            raise
                    raise

            edits.enter_context(patch.object(child, "wait", wait))
            return child

        class Reader:
            def __init__(self, stream):
                self.stream = stream

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return self.stream.__exit__(*args)

            def readline(self, size):
                nonlocal secondary, active
                scan = sys._getframe(1).f_locals["scan"]
                value = self.stream.readline(size)
                reads.append({"scan": scan, "bytes": len(value)})
                if scan == "final":
                    active = sys.exception()
                    if mode == "io":
                        raise OSError(5, "password=private-read")
                    if mode == "late":
                        return value
                    try:
                        interrupt("final-empty-read")
                    except KeyboardInterrupt as error:
                        secondary = error
                        raise
                return value

        def opened(path, *args, **kwargs):
            if path.name in ("0-pending.jsonl", "1-final-pending.jsonl") and args == ("rb",):
                if mode == "late" and sys._getframe(1).f_locals.get("scan") == "final":
                    pending.write_bytes((root / "startup.jsonl").read_bytes())
                return Reader(real_open(path, *args, **kwargs))
            return real_open(path, *args, **kwargs)

        def initialized(owner, child, end):
            real_init(owner, child, end)
            owners.append(owner)

        def closed(probe):
            real_close(probe)
            closes.append(probe.process.pid)

        def stopped(children, deadline, peers=()):
            stops.append(
                {"at": time.monotonic(), "deadline": deadline, "peers": [p.pid for p in peers]}
            )
            real_stop(children, deadline, peers)
            if mode == "timeout":
                pending.with_name("1-final-pending.jsonl").write_bytes(b"")

        try:
            with (
                patch.object(subprocess, "Popen", launch),
                patch.object(Path, "open", opened),
                patch.object(source.CreatorBindings, "__init__", initialized),
                patch.object(ProcessProbe, "close", closed),
                patch.object(source, "stop_owned", stopped),
            ):
                try:
                    source.run_control(
                        ["actor", "-n", "1"], root, 0.09 if mode == "timeout" else 45
                    )
                except (
                    KeyboardInterrupt,
                    AssertionError,
                    subprocess.TimeoutExpired,
                    OSError,
                    UnsafeArtifact,
                ) as error:
                    caught = error
            document = root / "long-export/long-w1/manifest.json"
            row = {
                "mode": mode,
                **snapshot(),
                "barriers": barriers,
                "reads": reads,
                "first_same": caught is first,
                "active_same": caught is active,
                "secondary_same": caught is secondary,
                "type": type(caught).__name__,
                "notes": getattr(caught, "__notes__", []),
                "note": control_note(caught),
                "root": {"pid": roots[0].pid, "created": root_birth},
                "worker": {"pid": held[0].process.pid, "created": held[0].created},
                "manifest": json.loads(document.read_bytes()) if document.is_file() else None,
            }
            (root / "observation.json").write_text(json.dumps(row, indent=2))
        finally:
            real_stop(roots, time.monotonic() + 3, [p.process for p in held])
            for child in roots:
                child.stdin.close()
            for probe in held:
                assert probe.record("after-rescue")["status"] == "proved-exited"
                probe.close()


if __name__ == "__main__":
    target, variant = Path(sys.argv[1]), sys.argv[2]
    if variant in ("root", "worker"):
        actor(target, variant)
    else:
        controller(target, variant)
