"""Bounded waits and cleanup for QA-owned processes only."""

from __future__ import annotations

import ctypes
import json
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

import psutil
from artifact_policy import Record
from diagnostic_sink import Sink
from windows_identity import WindowsIdentity


@dataclass(frozen=True, slots=True)
class ProcessProbe:
    """QA-owned query handle, acquired while the fixture's process is still alive."""

    process: psutil.Process
    created: float
    native: WindowsIdentity | None

    @classmethod
    def bind(cls, process: psutil.Process) -> ProcessProbe:
        created = process.create_time()
        native = None
        if sys.platform == "win32":
            try:
                native = WindowsIdentity.descendant(process.pid)
            except OSError:
                # An unavailable query is evidence of unknown state, never proof of exit.
                return cls(process, created, None)
        return cls(process, created, native)

    @property
    def key(self) -> str:
        birth = str(self.native.ticks) if self.native is not None else float(self.created).hex()
        return f"{self.process.pid}:{birth}"

    def record(self, stage: str) -> Record:
        record: Record = {
            "event": "observed",
            "scope": "qa",
            "stage": stage,
            "identity": self.key,
            "pid": self.process.pid,
            "created": self.created,
            "status": "unknown",
            "observed_at": time.monotonic(),
            "kind": "qa-owned-handle" if sys.platform == "win32" else "posix-process",
        }
        try:
            if sys.platform == "win32":
                if self.native is None:
                    return record
                api = self.native.kernel
                pid = api.GetProcessId(self.native.handle)
                created, exited, kernel, user = (wintypes.FILETIME() for _ in range(4))
                if not pid or not api.GetProcessTimes(
                    self.native.handle,
                    ctypes.byref(created),
                    ctypes.byref(exited),
                    ctypes.byref(kernel),
                    ctypes.byref(user),
                ):
                    return record
                ticks = (created.dwHighDateTime << 32) | created.dwLowDateTime
                result = api.WaitForSingleObject(self.native.handle, 0)
                record.update(pid=pid, ticks=str(ticks), exitcode=result)
                if pid == self.process.pid and ticks == self.native.ticks:
                    match result:
                        case 0:
                            record["status"] = "proved-exited"
                        case 258:
                            record["status"] = "live"
                return record
            process = psutil.Process(self.process.pid)
            if process.create_time() == self.created:
                record["status"] = (
                    "proved-exited" if process.status() == psutil.STATUS_ZOMBIE else "live"
                )
        except psutil.NoSuchProcess:
            record["status"] = "proved-exited"
        except (OSError, psutil.Error):
            record["status"] = "unknown"
        return record

    def close(self) -> None:
        if self.native is not None:
            self.native.close()


def record_peer_evidence(sink: Sink, artifacts: Path, ready: Sequence[Record]) -> None:
    """Project only finite identity/lifecycle fields; never publish argv, env or raw spool."""
    fields = {
        "event",
        "pid",
        "identity",
        "created",
        "ticks",
        "parent_identity",
        "role",
        "status",
        "last_live",
        "first_exit",
        "root_code",
        "exitcode",
        "observed_at",
        "deadline",
        "known",
        "interrupted",
        "complete",
        "observation_detached",
        "observer_failed",
        "observer_end",
    }
    events = {"binding", "root-exit", "exit", "post.begin", "observed", "post.end"}
    for filename in ("supervisor.jsonl", "post-root.jsonl"):
        records = read_records(artifacts / filename)
        assert len(records) <= 256, "Peer lifecycle receipt exceeded its finite bound."
        for record in records:
            if record["event"] in events:
                sink.emit(
                    {
                        **{key: value for key, value in record.items() if key in fields},
                        "scope": filename,
                        "observed_at": record.get("observed_at", record["monotonic"]),
                    }
                )
    for record in ready:
        sink.emit(record)


def read_records(path: Path) -> list[Record]:
    if not path.exists():
        return []
    with path.open("rb") as stream:
        data = stream.read(4 * 1024 * 1024 + 1)
    if len(data) > 4 * 1024 * 1024:
        raise AssertionError("Smoke receipt exceeded its bound.")
    # The writer may currently be completing its final record.
    return [json.loads(line) for line in data.splitlines(keepends=True) if line.endswith(b"\n")]


def wait_until(condition: Callable[[], bool], deadline: float) -> None:
    while not condition():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError("Bounded smoke readiness deadline expired.")
        threading.Event().wait(min(remaining, 0.01))


def stop_owned(
    children: Sequence[subprocess.Popen[bytes]],
    deadline: float,
    peers: Sequence[psutil.Process] = (),
) -> None:
    failures = []
    for child in children:
        if child.poll() is None:
            child.terminate()
    for child in children:
        try:
            child.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            child.kill()
            try:
                child.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                failures.append(child.pid)
    for peer in peers:
        try:
            if peer.status() == psutil.STATUS_ZOMBIE:
                continue
            peer.terminate()  # psutil checks the captured PID/creation identity before signalling.
            peer.wait(timeout=max(0.01, deadline - time.monotonic()))
        except psutil.NoSuchProcess:
            continue
        except psutil.TimeoutExpired:
            try:
                if peer.status() != psutil.STATUS_ZOMBIE:
                    peer.kill()
                    peer.wait(timeout=max(0.01, deadline - time.monotonic()))
            except psutil.NoSuchProcess:
                continue
            except (psutil.Error, OSError):
                failures.append(peer.pid)
        except (psutil.Error, OSError):
            failures.append(peer.pid)
    assert not failures, "QA-owned processes did not exit within the shared cleanup deadline."
