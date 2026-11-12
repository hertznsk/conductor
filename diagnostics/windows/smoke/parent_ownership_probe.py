"""Finite actors and a labelled native API substitute, never Windows ABI evidence."""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import time
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import TypedDict

import psutil
from artifact_policy import Sanitizer
from diagnostic_sink import Sink
from process_identity import Identity
from smoke import long_ownership, support
from smoke.support import wait_until
from windows_identity import WindowsIdentity

EPOCH = 116444736000000000


class NativeChild(subprocess.Popen[bytes]):
    """Synthetic original Popen boundary; no process is spawned in finite native tests."""

    def __init__(self) -> None:
        self.pid = 100
        self.returncode = None


@dataclass(frozen=True, slots=True)
class ActorCase:
    variant: str
    depth: int
    promote: bool
    survive: bool


class Attempt(TypedDict):
    pid: int
    role: str
    refused: bool


class Binding(TypedDict):
    pid: int
    parent: int
    key: str
    created: float
    kind: str
    status: str


class Stop(TypedDict):
    peers: list[int]
    at: float
    deadline: float


class Proof(TypedDict):
    variant: str
    depth: int
    promote: bool
    survive: bool
    old_sha: str | None
    attempts: list[Attempt]
    bindings: list[Binding]
    stops: list[Stop]
    closes: list[int]
    native_open: list[tuple[int, int, bool]]
    native_close_count: int
    wait_ms: list[int]
    primary: str
    note: str | None
    native_abi: str
    resources: dict[str, list[int]]


def ticks(created: float) -> int:
    """Choose simulated integer ticks whose seconds round to the observed POSIX birth."""
    return EPOCH + round(created * 10_000_000)


class NativeBoundary:
    """Simulate kernel calls only; the owner and ProcessProbe predicates execute unchanged."""

    def __init__(self) -> None:
        self.lookup = psutil.Process
        self.births: dict[int, int] = {}
        self.opened: list[tuple[int, int, bool]] = []
        self.closed: list[int] = []
        self.states: dict[int, int] = {}
        self.handles: dict[int, int] = {}
        self.waits: list[int] = []

    def OpenProcess(self, rights: int, inherit: bool, pid: int) -> int:
        self.opened.append((pid, rights, inherit))
        handle = 1_000_000 + len(self.opened)
        self.handles[handle] = pid
        return handle

    def GetProcessId(self, handle: int) -> int:
        return self.handles.get(handle, handle)

    def GetProcessTimes(self, handle, created, exited, kernel, user) -> bool:
        pid = self.handles.get(handle, handle)
        birth = self.births.get(pid)
        if birth is None:
            birth = ticks(self.lookup(pid).create_time())
        value = ctypes.cast(created, ctypes.POINTER(wintypes.FILETIME)).contents
        value.dwHighDateTime, value.dwLowDateTime = birth >> 32, birth & 0xFFFFFFFF
        return True

    def WaitForSingleObject(self, handle: int, milliseconds: int) -> int:
        self.waits.append(milliseconds)
        pid = self.handles.get(handle, handle)
        if pid in self.states:
            return self.states[pid]
        try:
            return 0 if self.lookup(pid).status() == psutil.STATUS_ZOMBIE else 258
        except psutil.NoSuchProcess:
            return 0

    def CloseHandle(self, handle: int) -> bool:
        assert handle not in self.closed
        self.closed.append(handle)
        return True


def install_native(patch, boundary: NativeBoundary) -> None:
    """Replace unavailable Windows ABI calls on Linux, retaining original proof operations."""
    import windows_identity

    class Anchor:
        @staticmethod
        def child(child: subprocess.Popen[bytes]) -> Identity:
            # The synthetic handle belongs only to this identity, never to the real Popen.
            native = WindowsIdentity(child.pid, owned=False)
            return Identity(child.pid, native.ticks / 10_000_000 - 11_644_473_600, native)

    api = SimpleNamespace(
        Process=boundary.lookup,
        Error=psutil.Error,
        NoSuchProcess=psutil.NoSuchProcess,
        STATUS_ZOMBIE=psutil.STATUS_ZOMBIE,
        TimeoutExpired=psutil.TimeoutExpired,
    )
    patch.setattr(windows_identity, "kernel_api", lambda: boundary)
    patch.setattr(long_ownership, "kernel_api", lambda: boundary)
    patch.setattr(long_ownership, "Identity", Anchor)
    patch.setattr(long_ownership, "sys", SimpleNamespace(platform="win32", exception=sys.exception))
    patch.setattr(support, "sys", SimpleNamespace(platform="win32"))
    patch.setattr(long_ownership, "psutil", api)
    patch.setattr(support, "psutil", api)


def header(root: Path, role: str) -> None:
    """Publish genuine self PID, birth and parent; optional simulated native key is labelled."""
    process = psutil.Process()
    created = process.create_time()
    if os.environ.get("QA_NATIVE"):
        key = f"{process.pid}:{ticks(created)}"
    else:
        native = WindowsIdentity.descendant(process.pid) if sys.platform == "win32" else None
        try:
            key = Identity(process.pid, created, native).key
        finally:
            if native is not None:
                native.close()
    with_sink = Sink(root / f"{process.pid}-{role}.jsonl", Sanitizer({}))
    with_sink.emit(
        {
            "event": "observed",
            "kind": "process",
            "stage": "startup",
            "status": "live",
            "pid": process.pid,
            "created": created,
            "identity": key,
            "parent": process.ppid(),
            "worker": role,
            "role": role,
            "scope": "long-control",
        }
    )
    with_sink.close()


def actor(root: Path, level: int) -> None:
    """Own one pipe-linked child; a query survivor waits for explicit QA rescue."""
    depth = int(os.environ["QA_DEPTH"])
    if level == depth:
        header(root, "gw0" if depth else "controller")
        sys.stdin.buffer.read(1)
        return
    with subprocess.Popen(
        [sys.executable, "-m", "smoke.parent_ownership_probe", str(root), str(level + 1)],
        stdin=subprocess.PIPE,
    ) as child:
        if level == 1 and os.environ.get("QA_PROMOTE"):
            wait_until(lambda: (root.parent / "worker.attempted").exists(), time.monotonic() + 10)
            header(root, "controller")
        sys.stdin.buffer.read(1)
        if level == 1 and os.environ.get("QA_SURVIVE"):
            wait_until(lambda: (root.parent / "rescue").exists(), time.monotonic() + 15)
        assert child.stdin is not None
        child.stdin.close()
        child.wait(timeout=5)


if __name__ == "__main__":
    actor(Path(sys.argv[1]), int(sys.argv[2]))
