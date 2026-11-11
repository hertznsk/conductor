"""Identity binding and physical observation, distinct from the Popen child outcome."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from enum import StrEnum

import psutil
from artifact_policy import Record
from windows_identity import WindowsIdentity


class State(StrEnum):
    LIVE = "live"
    EXITED = "proved-exited"
    MISMATCH = "identity-mismatch"
    UNAVAILABLE = "unavailable"
    AMBIGUOUS = "ambiguous"


@dataclass(slots=True)
class BindingError(Exception):
    """Typed binding refusal with the mutable traceback required by exception propagation."""

    state: State
    reason: str


@dataclass(slots=True)
class Identity:
    """Accumulate observation intervals while retaining the same immutable process key."""

    pid: int
    created: float
    native: WindowsIdentity | None = None
    parent: str | None = None
    role: str = "unknown"
    state: State = State.LIVE
    last_live: float | None = None
    first_exit: float | None = None

    @property
    def key(self) -> str:
        birth = str(self.native.ticks) if self.native is not None else float(self.created).hex()
        return f"{self.pid}:{birth}"

    @classmethod
    def child(cls, child: subprocess.Popen[bytes]) -> Identity:
        if sys.platform == "win32":
            native = WindowsIdentity.child(child)
            return cls(child.pid, native.ticks / 10_000_000 - 11_644_473_600, native, role="root")
        # No poll/wait precedes this binding. An unreaped child, including zombie, owns its PID.
        if child.returncode is not None or signal.getsignal(signal.SIGCHLD) == signal.SIG_IGN:
            raise BindingError(State.AMBIGUOUS, "child-reaped-or-reaper-ambiguous")
        process = psutil.Process(child.pid)
        if process.pid != child.pid or process.ppid() != os.getpid():
            raise BindingError(State.MISMATCH, "child-parent-mismatch")
        identity = cls(process.pid, process.create_time(), role="root")
        identity.observe()
        return identity

    @classmethod
    def descendant(cls, process: psutil.Process, parent: Identity) -> Identity:
        native = WindowsIdentity.descendant(process.pid) if sys.platform == "win32" else None
        try:
            fresh = psutil.Process(process.pid)
            if (
                fresh.create_time() != process.create_time()
                or fresh.ppid() != parent.pid
                or parent.observe() != State.LIVE
                or fresh.create_time() < parent.created
            ):
                raise OSError("descendant-edge-ambiguous")
            return cls(fresh.pid, fresh.create_time(), native, parent.key)
        except (OSError, psutil.Error):
            if native is not None:
                native.close()
            raise

    def observe(self) -> State:
        if self.state == State.EXITED:
            return self.state
        now = time.monotonic()
        try:
            if self.native is not None:
                current = State.EXITED if self.native.exited() else State.LIVE
            else:
                process = psutil.Process(self.pid)
                if process.create_time() != self.created:
                    current = State.MISMATCH
                elif process.status() == psutil.STATUS_ZOMBIE:
                    current = State.EXITED
                else:
                    current = State.LIVE
        except psutil.NoSuchProcess:
            current = State.EXITED
        except (OSError, psutil.Error):
            current = State.UNAVAILABLE
        self.state = current
        if current == State.LIVE:
            self.last_live = now
        elif current == State.EXITED:
            self.first_exit = now
        return current

    def record(self, event: str) -> Record:
        return {
            "event": event,
            "pid": self.pid,
            "identity": self.key,
            "created": self.created,
            "ticks": str(self.native.ticks) if self.native else None,
            "parent_identity": self.parent,
            "role": self.role,
            "status": self.state.value,
            "last_live": self.last_live,
            "first_exit": self.first_exit,
        }

    def close(self) -> None:
        if self.native is not None:
            self.native.close()
