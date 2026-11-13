"""Observe actual Popen owners without confusing borrowed or synthetic handles."""

from __future__ import annotations

import ctypes
import subprocess
import sys
import threading
import time
import weakref
from ctypes import wintypes
from types import FrameType
from typing import Protocol, runtime_checkable

from smoke.long_ownership import CreatorBindings
from smoke.parent_resource_records import Finalization, Query, Refs, Root, Thread, ThreadSource
from smoke.support import ProcessProbe
from windows_identity import kernel_api

POPEN = subprocess.Popen
STREAM_NAMES: tuple[ThreadSource, ...] = ("stdout_thread", "stderr_thread", "_stdin_thread")


@runtime_checkable
class HandleOwner(Protocol):
    closed: bool

    def Close(self) -> None: ...

    def __int__(self) -> int: ...


def stream_threads(child: subprocess.Popen[bytes]) -> tuple[threading.Thread, ...]:
    return tuple(
        thread
        for name in STREAM_NAMES
        if isinstance(thread := vars(child).get(name), threading.Thread)
    )


def thread_row(thread: threading.Thread, source: ThreadSource) -> Thread:
    return Thread(
        source,
        thread.ident,
        thread.native_id,
        thread.ident is not None,
        thread.daemon,
        thread is threading.current_thread(),
    )


class State:
    """Retain weak owner references and scalar evidence through the six stages."""

    def __init__(self, synthetic: bool) -> None:
        self.synthetic = synthetic
        self.child: weakref.ReferenceType[subprocess.Popen[bytes]] | None = None
        self.owner: weakref.ReferenceType[CreatorBindings] | None = None
        self.queries: dict[str, Query] = {}
        self.closes: dict[str, int] = {}
        self.used: dict[str, int] = {}
        self.finalization: Finalization = "not-attempted"
        self.close_enter: int | None = None
        self.close_return: int | None = None
        self.close_error: int | None = None
        self.joined: tuple[Thread, ...] = ()
        self.api = kernel_api() if sys.platform == "win32" else None
        if self.api is not None:
            self.api.GetHandleInformation.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(wintypes.DWORD),
            ]
            self.api.GetHandleInformation.restype = wintypes.BOOL

    def root(self) -> subprocess.Popen[bytes] | None:
        return self.child() if self.child is not None else None

    def flags(self, handle: int) -> tuple[bool, int | None, int | None]:
        assert sys.platform == "win32"
        assert self.api is not None
        value = wintypes.DWORD()
        ok = bool(self.api.GetHandleInformation(handle, ctypes.byref(value)))
        return ok, value.value if ok else None, None if ok else ctypes.get_last_error()

    def root_row(self) -> Root | None:
        child = self.root()
        if child is None:
            return None
        handle = vars(child).get("_handle")
        number, closed = None, None
        ok, flags, error, native_pid, ticks = None, None, None, None, None
        if isinstance(handle, HandleOwner):
            number, closed = hex(int(handle)), handle.closed
            # Never query a numeric handle again after any owner-close attempt.
            if (
                sys.platform == "win32"
                and self.api is not None
                and not closed
                and self.close_enter is None
            ):
                ok, flags, error = self.flags(int(handle))
                if ok:
                    native_pid = self.api.GetProcessId(int(handle))
                    birth, exit_time, kernel, user = (wintypes.FILETIME() for _ in range(4))
                    if self.api.GetProcessTimes(
                        int(handle),
                        ctypes.byref(birth),
                        ctypes.byref(exit_time),
                        ctypes.byref(kernel),
                        ctypes.byref(user),
                    ):
                        ticks = str((birth.dwHighDateTime << 32) | birth.dwLowDateTime)
                    else:
                        error = ctypes.get_last_error()
        streams = (child.stdin, child.stdout, child.stderr)
        return Root(
            child.pid,
            number,
            closed,
            child.returncode,
            ok,
            flags,
            error,
            native_pid,
            ticks,
            all(stream is None or stream.closed for stream in streams),
        )

    def query(self, probe: ProcessProbe) -> None:
        native = probe.native
        if native is None:
            return
        previous = self.queries.get(probe.key)
        flags = previous.flags if previous else None
        flags_at = previous.flags_at_ns if previous else None
        if (
            self.api is not None
            and native.owned
            and not native.closed
            and not self.synthetic
            and self.closes.get(probe.key, 0) == 0
        ):
            _, flags, _ = self.flags(native.handle)
            flags_at = time.monotonic_ns()
        child = self.root()
        handle = vars(child).get("_handle") if child is not None else None
        self.queries[probe.key] = Query(
            probe.process.pid,
            probe.key,
            "synthetic" if self.synthetic else "real-owned" if native.owned else "real-borrowed",
            hex(native.handle),
            native.handle == int(handle)
            if not self.synthetic and not native.owned and isinstance(handle, HandleOwner)
            else None,
            native.owned,
            native.closed,
            getattr(native.close_error, "winerror", None),
            self.closes.get(probe.key, 0),
            flags,
            flags_at,
            self.used.get(probe.key),
        )

    def refs(self, frame: FrameType | None) -> Refs:
        child = self.root()
        owner = self.owner() if self.owner is not None else None
        local = frame.f_locals if frame is not None else {}
        roots, patch, primary = local.get("roots", ()), local.get("patch"), local.get("primary")
        return Refs(
            frame is not None,
            child is not None and any(root is child for root in roots),
            child is not None and owner is not None and owner.child is child,
            child is not None
            and any(
                cell.cell_contents is child for cell in getattr(child.wait, "__closure__", ()) or ()
            ),
            child is not None
            and patch is not None
            and any(entry[0] is child for entry in patch._setattr),
            isinstance(primary, BaseException) and primary.__traceback__ is not None,
        )

    def threads(self) -> tuple[Thread, ...]:
        child = self.root()
        owned = stream_threads(child) if child is not None else ()
        rows = [thread_row(t, "other") for t in threading.enumerate()[:65] if t not in owned]
        if child is not None:
            for name in STREAM_NAMES:
                thread = vars(child).get(name)
                if isinstance(thread, threading.Thread):
                    rows.append(
                        next(
                            (
                                row
                                for row in self.joined
                                if row.source == name and row.ident == thread.ident
                            ),
                            thread_row(thread, name),
                        )
                    )
        return tuple(rows)

    def finalize(self, permitted: bool) -> None:
        child = self.root()
        if not permitted or child is None:
            self.finalization = "unsafe-not-attempted"
            return
        if self.api is None:
            self.finalization = "windows-unrun"
            return
        root = self.root_row()
        assert root is not None
        if not (
            root.returncode is not None
            and root.io_closed
            and root.flags_ok
            and root.flags is not None
            and root.flags & 2 == 0
            and root.closed is False
            and root.native_pid == root.pid
            and root.ticks is not None
        ):
            self.finalization = "unsafe-not-attempted"
            return
        rows = []
        for thread in stream_threads(child):
            source = next(name for name in STREAM_NAMES if vars(child).get(name) is thread)
            row = thread_row(thread, source)
            if not row.started or row.current:
                self.finalization = "unsafe-not-attempted"
                return
            enter = time.monotonic_ns()
            thread.join(0)
            returned = time.monotonic_ns()
            alive = thread.is_alive()
            rows.append(
                Thread(
                    row.source,
                    row.ident,
                    row.native_id,
                    row.started,
                    row.daemon,
                    row.current,
                    enter,
                    returned,
                    alive,
                )
            )
            self.joined = tuple(rows)
            if alive:
                self.finalization = "unsafe-not-attempted"
                return
        handle = vars(child).get("_handle")
        if (
            not isinstance(handle, HandleOwner)
            or handle.closed
            or type(handle) is not getattr(subprocess, "Handle", None)
            or self.close_enter is not None
        ):
            self.finalization = "unsafe-not-attempted"
            return
        self.close_enter = time.monotonic_ns()
        try:
            handle.Close()
        except OSError as error:
            self.close_error = getattr(error, "winerror", None)
            self.finalization = "close-failed"
        else:
            self.close_return = time.monotonic_ns()
            self.finalization = "close-returned"
