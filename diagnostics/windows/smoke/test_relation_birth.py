"""Pinned psutil birth representation; substituted boundaries are not Windows ABI proof."""

from __future__ import annotations

import ctypes
from collections.abc import Iterator
from contextlib import ExitStack
from ctypes import wintypes
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Final

import pytest
import windows_identity
from artifact_policy import UnsafeArtifact
from smoke import support
from smoke import test_launch_relations as relations
from smoke.long_records import Startup

PID: Final = 7068
TICKS: Final = 134389557054651461
PSUTIL_CREATED: Final = 1794482105.4651461


@dataclass
class Observations:
    """Mutable hardware observations and call witnesses for the real binding code."""

    created: float = PSUTIL_CREATED
    native_pid: int | None = None
    record_ticks: int = TICKS
    wait: int = 258
    available: bool = True
    times: dict[int, int] = field(default_factory=dict)
    opened: list[int] = field(default_factory=list)
    closed: list[int] = field(default_factory=list)
    rights: list[int] = field(default_factory=list)
    waits: list[int] = field(default_factory=list)

    def OpenProcess(self, access: int, inherit: bool, pid: int) -> int:
        self.rights.append(access)
        assert not inherit
        if not self.available:
            raise OSError("controlled-query-unavailable")
        self.opened.append(pid)
        return pid

    def GetProcessId(self, handle: int) -> int:
        return handle if self.native_pid is None else self.native_pid

    def GetProcessTimes(
        self,
        handle: int,
        created: ctypes.c_void_p,
        exited: ctypes.c_void_p,
        kernel: ctypes.c_void_p,
        user: ctypes.c_void_p,
    ) -> bool:
        self.times[handle] = self.times.get(handle, 0) + 1
        ticks = TICKS if self.times[handle] == 1 else self.record_ticks
        value = ctypes.cast(created, ctypes.POINTER(wintypes.FILETIME)).contents
        value.dwHighDateTime, value.dwLowDateTime = ticks >> 32, ticks & 0xFFFFFFFF
        return True

    def WaitForSingleObject(self, handle: int, milliseconds: int) -> int:
        assert milliseconds == 0
        self.waits.append(self.wait)
        return self.wait

    def CloseHandle(self, handle: int) -> bool:
        self.closed.append(handle)
        return True


@pytest.fixture
def observations(monkeypatch: pytest.MonkeyPatch) -> Iterator[Observations]:
    boundary = Observations()

    class Process:
        def __init__(self, pid: int) -> None:
            self.pid = pid

        def create_time(self) -> float:
            return boundary.created

        def ppid(self) -> int:
            return 5876

    monkeypatch.setattr(relations, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(support, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(relations.psutil, "Process", Process)
    monkeypatch.setattr(windows_identity, "kernel_api", lambda: boundary)
    yield boundary
    assert boundary.rights == [0x101000] * len(boundary.rights)
    assert sorted(boundary.closed) == sorted(boundary.opened)


def test_query_matches_pinned_psutil_birth(observations: Observations) -> None:
    # Requirement: a new same-PID query binds the pinned birth and reaches native live checks.
    held: dict[int, relations.Node] = {}
    assert PID not in held
    with ExitStack() as handles:
        node = relations.query(PID, held, handles)
        assert node.probe.created == PSUTIL_CREATED
        assert node.probe.key == "7068:134389557054651461"
        assert node.probe.native is not None and node.probe.native.owned
        assert observations.waits == [258]
        assert node.live()
        assert observations.waits == [258, 258]
        assert observations.closed == []
    assert observations.closed == [PID]


@pytest.mark.parametrize(
    ("fault", "reason"),
    [
        ("pid", "native-birth"),
        ("birth", "native-birth"),
        ("unavailable", "native-unavailable"),
        ("exited", "query-not-live"),
        ("unknown", "query-not-live"),
        ("key", "query-not-live"),
    ],
)
def test_query_refuses_incompatible_observations(
    observations: Observations, fault: str, reason: str
) -> None:
    # Requirement: corrected seconds never admit wrong PID/birth or unknown/exited native keys.
    match fault:
        case "pid":
            observations.native_pid = PID + 1
        case "birth":
            observations.created = 1794482106.4651461
        case "unavailable":
            observations.available = False
        case "exited":
            observations.wait = 0
        case "unknown":
            observations.wait = 0xFFFFFFFF
        case "key":
            # The adjacent lower tick shares the pinned psutil double, but not the exact key.
            observations.record_ticks = TICKS - 1
        case _:
            pytest.fail("Unknown boundary stimulus.")
    with ExitStack() as handles, pytest.raises(UnsafeArtifact) as caught:
        relations.query(PID, {}, handles)
    assert caught.value.reason == reason
    if fault == "key":
        assert observations.waits == [258]


def test_snapshot_refuses_exact_startup_key_mismatch(observations: Observations) -> None:
    # Requirement: a startup key differing by one tick cannot inherit a live query's validity.
    with ExitStack() as handles:
        root = relations.query(PID, {}, handles)
        starts = [
            Startup(PID, PSUTIL_CREATED, f"{PID}:{TICKS}", 5876, "controller"),
            Startup(7080, PSUTIL_CREATED, f"7080:{TICKS - 1}", 5876, "gw0"),
            Startup(7081, PSUTIL_CREATED, f"7081:{TICKS}", 5876, "gw1"),
        ]
        receipt = relations.snapshot(root, starts, handles)
        assert receipt["outcome"] == "incomplete"
        worker = next(row for row in receipt["nodes"] if row[1] == 7080)
        assert worker[4] is False and worker[5] is True
        assert receipt["edges"] == []
