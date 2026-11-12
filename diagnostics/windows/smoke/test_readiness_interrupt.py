"""Exercise real runtime signals and owned lifecycle boundaries without a console dependency."""

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
from smoke.support import ProcessProbe, stop_owned


def _run_controller(root: Path, mode: str, external: bool):
    """Own a controller and record all pre-rescue effects; external sending is Linux manual QA."""
    events = []
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(2)
        server.settimeout(15)
        env = {
            **os.environ,
            "QA_SIGNAL_PORT": str(server.getsockname()[1]),
            "PYTHONPATH": os.pathsep.join(sys.path),
        }
        with (root / "controller.log").open("wb") as output:
            foreign = subprocess.Popen(
                [psutil.Process().exe(), "-c", "import sys;sys.stdin.buffer.read(1)"],
                stdin=subprocess.PIPE,
            )
            foreign_probe = ProcessProbe.bind(psutil.Process(foreign.pid))
            child = subprocess.Popen(
                [psutil.Process().exe(), "-m", "smoke.readiness_interrupt_probe", str(root), mode],
                env=env,
                stdout=output,
                stderr=subprocess.STDOUT,
            )
            held = ProcessProbe.bind(psutil.Process(child.pid))
            try:
                count = (
                    2
                    if mode in ("repeat", "bound", "repeat-publication")
                    else (0 if mode in ("io", "late") else 1)
                )
                for _ in range(count):
                    connection, _ = server.accept()
                    with connection, connection.makefile("rb") as stream:
                        event = json.loads(stream.readline(65537))
                        assert psutil.Process(child.pid).create_time() == held.created
                        assert held.record("pre-signal")["status"] == "live"
                        assert foreign_probe.record("pre-signal")["status"] == "live"
                        events.append(
                            {
                                **event,
                                "controller": child.pid,
                                "birth": held.created,
                                "at": time.monotonic(),
                            }
                        )
                        if external:
                            child.send_signal(signal.SIGINT)
                        else:
                            connection.sendall(b"S")
                        assert stream.read(1) == b""
                assert child.wait(timeout=15) == 0
                observation = json.loads((root / "observation.json").read_bytes())
                observation["sender"] = {
                    "events": events,
                    "external": external,
                    "foreign_live": foreign.poll() is None,
                    "controller": child.pid,
                    "birth": held.created,
                    "foreign": {"pid": foreign.pid, "created": foreign_probe.created},
                }
            finally:
                stop_owned([child, foreign], time.monotonic() + 3)
                assert foreign.stdin is not None
                foreign.stdin.close()
                assert held.record("closed")["status"] == "proved-exited"
                assert foreign_probe.record("closed")["status"] == "proved-exited"
                held.close()
                foreign_probe.close()
    return observation


def run_probe(root: Path, mode: str, external: bool = False):
    """Measure after the owning sender frame and its Popen handles have been released."""
    baseline = resources()
    observation = _run_controller(root, mode, external)
    after = resources()
    assert after == baseline
    observation["resources"] = {"before": baseline, "after": after}
    (root / "proof.json").write_text(json.dumps(observation, indent=2))
    return observation


def resources() -> list[int]:
    """Count handles through the platform API without treating absence as zero."""
    owner = psutil.Process()
    if sys.platform == "win32":
        assert hasattr(owner, "num_handles")
        count = owner.num_handles()
    else:
        assert hasattr(owner, "num_fds")
        count = owner.num_fds()
    return [owner.num_threads(), len(owner.children()), count]


def assert_repaired(row) -> None:
    """Assert lifecycle, primary semantics and existing strict evidence, not note prose."""
    assert not row["root_live"] and row["sender"]["foreign_live"]
    assert row["peer"] == "proved-exited"
    assert len(row["stops"]) == 1
    assert 0 < row["stops"][0]["deadline"] - row["stops"][0]["at"] <= 3
    assert sorted(map(int, row["grants"])) == sorted(row["closes"])
    repeat = row["mode"] in ("repeat", "bound", "repeat-publication")
    if repeat:
        assert any(r["scan"] == "final" and r["bytes"] == 0 for r in row["reads"])
        assert row["type"] == "KeyboardInterrupt" and row["first_same"]
        assert not row["secondary_same"]
        first, second = row["sender"]["events"]
        assert first["stage"] == "wait-timeout" and second["stage"] == "final-empty-read"
        assert len(second["stops"]) == 1 and not second["root_live"]
        assert sorted(map(int, second["grants"])) == sorted(second["closes"])
        secondary_notes = [n for n in row["notes"] if "KeyboardInterrupt" in n and "final" in n]
        assert len(secondary_notes) == 1 and "password=" not in secondary_notes[0]
    elif row["mode"] == "normal1":
        assert row["type"] == "AssertionError" and row["active_same"]
    elif row["mode"] == "timeout":
        assert row["type"] == "TimeoutExpired" and row["active_same"]
    elif row["mode"] in ("normal0", "normal0-publication"):
        assert row["type"] == "KeyboardInterrupt" and row["secondary_same"]
    else:
        assert row["type"] == "UnsafeArtifact"
    if row["mode"] == "io":
        assert "owner=final:read:" in row["note"] and ":OSError:5:" in row["note"]
    if row["mode"] == "late":
        assert any(r["scan"] == "final" and r["bytes"] > 0 for r in row["reads"])
    granted_peer = row["grants"].get(str(row["worker"]["pid"])) == "source"
    assert granted_peer == (row["mode"] == "bound")
    assert row["stops"][0]["peers"] == ([row["worker"]["pid"]] if granted_peer else [])
    if not granted_peer:
        assert row["eof"]
    assert row["note"] and row["note"].isascii() and len(row["note"].encode()) <= 2048
    assert "password=" not in row["note"]
    if not row["mode"].endswith("publication"):
        metadata = row["manifest"]
        assert metadata and not metadata["complete"] and not metadata["cleanup_complete"]
        assert metadata["root_code"] == (
            None if repeat or row["mode"] == "timeout" else (1 if row["mode"] == "normal1" else 0)
        )
        assert metadata["timeout"] == (row["mode"] == "timeout")
    else:
        assert row["manifest"] is None


@pytest.mark.parametrize(
    "mode",
    [
        "repeat",
        "bound",
        "normal0",
        "normal1",
        "timeout",
        "io",
        "late",
        "repeat-publication",
        "normal0-publication",
    ],
)
def test_optional_final_observation_preserves_owned_cleanup_and_primary(
    tmp_path: Path,
    mode: str,
) -> None:
    # Requirement: actual signal/IO failures in final observation cannot bypass cleanup or primary.
    assert_repaired(run_probe(tmp_path, mode))
