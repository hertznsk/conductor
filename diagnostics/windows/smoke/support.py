"""Bounded waits and cleanup for QA-owned processes only."""

from __future__ import annotations

import json
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path

import psutil
from artifact_policy import Record


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
