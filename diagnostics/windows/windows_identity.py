"""CPython 3.13 Windows boundary. Borrow the actual Popen handle; never re-open its PID."""

from __future__ import annotations

import ctypes
import subprocess
from ctypes import wintypes


def popen_handle(child: subprocess.Popen[bytes]) -> int:
    """Parse the private CPython Handle(int) boundary; never perform a PID lookup."""
    handle = vars(child).get("_handle")
    if not isinstance(handle, int):
        raise OSError("unsupported-cpython-process-handle")
    return int(handle)


def kernel_api() -> ctypes.WinDLL:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetProcessId.argtypes = [wintypes.HANDLE]
    kernel.GetProcessId.restype = wintypes.DWORD
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    return kernel


class WindowsIdentity:
    """One process object. Owned descendant handles close; the borrowed root never does."""

    def __init__(self, handle: int, owned: bool) -> None:
        self.handle = handle
        self.owned = owned
        self.closed = False
        self.close_error: OSError | None = None
        self.kernel = kernel_api()
        self.pid = self.kernel.GetProcessId(handle)
        if not self.pid:
            raise ctypes.WinError(ctypes.get_last_error())
        created, exited, kernel_time, user_time = (wintypes.FILETIME() for _ in range(4))
        if not self.kernel.GetProcessTimes(
            handle,
            ctypes.byref(created),
            ctypes.byref(exited),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        self.ticks = (created.dwHighDateTime << 32) | created.dwLowDateTime

    @classmethod
    def child(cls, child: subprocess.Popen[bytes]) -> WindowsIdentity:
        # Private CPython adapter: hosted Windows/Python 3.13 smoke is a publication gate.
        identity = cls(popen_handle(child), False)
        if identity.pid != child.pid:
            raise OSError("actual-child-handle-pid-mismatch")
        return identity

    @classmethod
    def descendant(cls, pid: int) -> WindowsIdentity:
        kernel = kernel_api()
        handle = kernel.OpenProcess(0x1000 | 0x100000, False, pid)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return cls(handle, True)
        except OSError:
            kernel.CloseHandle(handle)
            raise

    def exited(self) -> bool:
        state = self.kernel.WaitForSingleObject(self.handle, 0)
        match state:
            case 0:
                return True
            case 258:
                return False
            case _:
                raise ctypes.WinError(ctypes.get_last_error())

    def close(self) -> None:
        if self.owned and not self.closed:
            if self.close_error is not None:
                raise self.close_error
            if not self.kernel.CloseHandle(self.handle):
                self.close_error = ctypes.WinError(ctypes.get_last_error())
                raise self.close_error
            self.closed = True
