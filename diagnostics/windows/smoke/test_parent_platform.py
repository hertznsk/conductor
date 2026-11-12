"""Platform fixture contracts; native API substitutions on Linux are not Windows ABI proof."""

import json
import subprocess
import sys
from collections.abc import Generator
from pathlib import Path
from types import SimpleNamespace

import psutil
import pytest
import windows_identity
from artifact_policy import Sanitizer
from smoke import long_ownership
from smoke import parent_ownership_probe as fixture
from smoke.long_records import control_records
from smoke.parent_ownership_probe import EPOCH, NativeBoundary, install_native, ticks
from smoke.test_readiness_interrupt import resources


class QueryCalls(NativeBoundary):
    """Record existing simulated API calls while executing their original implementations."""

    def __init__(self, denied: bool = False) -> None:
        super().__init__()
        self.denied = denied
        self.events: list[str] = []

    def OpenProcess(self, rights: int, inherit: bool, pid: int) -> int:
        self.events.append("open")
        if self.denied:
            raise PermissionError(13, "query-unavailable")
        return super().OpenProcess(rights, inherit, pid)

    def GetProcessId(self, handle: int) -> int:
        self.events.append("pid")
        return super().GetProcessId(handle)

    def GetProcessTimes(self, handle, created, exited, kernel, user) -> bool:
        self.events.append("times")
        return super().GetProcessTimes(handle, created, exited, kernel, user)

    def CloseHandle(self, handle: int) -> bool:
        self.events.append("close")
        return super().CloseHandle(handle)


@pytest.fixture(autouse=True)
def restored_resources(tmp_path: Path) -> Generator[None]:
    before = resources()
    yield
    after = resources()
    (tmp_path / "platform-resources.json").write_text(
        json.dumps({"before": before, "after": after})
    )
    assert after == before


@pytest.mark.parametrize("finish", ["natural", "terminate"])
def test_substitute_preserves_original_popen_state_and_lifecycle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, finish: str
) -> None:
    # Requirement: identity-only substitution never adds/replaces a real Popen handle or state.
    api = QueryCalls()
    with subprocess.Popen(
        [sys.executable, "-c", "import sys\nsys.stdin.buffer.read(1)\nsys.exit(7)\n"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
    ) as child:
        original = vars(child).copy()
        install_native(monkeypatch, api)
        identity = long_ownership.Identity.child(child)
        preserved = vars(child) == original
        (tmp_path / "handle-binding.json").write_text(
            json.dumps(
                {
                    "pid": child.pid,
                    "handle_field_before": "_handle" in original,
                    "handle_field_after": "_handle" in vars(child),
                    "state_preserved": preserved,
                    "native_api": "substituted",
                }
            )
        )
        assert preserved
        assert child.poll() is None
        assert identity.pid == child.pid and identity.native is not None
        assert not identity.native.owned
        assert child.stdin is not None
        if finish == "natural":
            child.stdin.write(b"G")
            child.stdin.flush()
            assert child.wait(timeout=5) == 7
        else:
            child.terminate()
            assert child.wait(timeout=5) != 7
        assert child.poll() == child.returncode
        identity.close()
        assert api.closed == []
        (tmp_path / "platform-lifecycle.json").write_text(
            json.dumps(
                {
                    "pid": child.pid,
                    "finish": finish,
                    "returncode": child.returncode,
                    "state_preserved": preserved,
                    "calls": api.events,
                    "native_close_count": len(api.closed),
                }
            )
        )


@pytest.mark.parametrize("mode", ["posix", "native", "synthetic", "unavailable"])
def test_header_uses_canonical_platform_key_and_closes_query(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    # Requirement: genuine psutil birth/parent corroborate full native ticks, with no hex fallback.
    process = psutil.Process()
    created, parent = process.create_time(), process.ppid()
    api = QueryCalls(denied=mode == "unavailable")
    birth = next(
        value
        for value in range(ticks(created) - 2, ticks(created) + 3)
        if float(value - EPOCH) / 10_000_000 == created and int(float(value)) != value
    )
    api.births[process.pid] = birth
    monkeypatch.setattr(windows_identity, "kernel_api", lambda: api)
    monkeypatch.setattr(
        fixture, "sys", SimpleNamespace(platform="linux" if mode == "posix" else "win32")
    )
    monkeypatch.delenv("QA_NATIVE", raising=False)
    if mode == "synthetic":
        monkeypatch.setenv("QA_NATIVE", "1")
    if mode == "unavailable":
        with pytest.raises(PermissionError):
            fixture.header(tmp_path, "controller")
        assert api.events == ["open"] and not api.closed
        assert list(tmp_path.glob("*-controller.jsonl")) == []
    else:
        fixture.header(tmp_path, "controller")
        path = tmp_path / f"{process.pid}-controller.jsonl"
        startup = control_records(path.read_bytes(), Sanitizer({})).startup
        assert (startup.pid, startup.created, startup.parent) == (process.pid, created, parent)
        expected = f"{process.pid}:{float(created).hex()}"
        if mode == "synthetic":
            expected = f"{process.pid}:{ticks(created)}"
        if mode == "native":
            expected = f"{process.pid}:{birth}"
            assert api.events == ["open", "pid", "times", "close"]
            assert api.opened == [(process.pid, 0x101000, False)]
            assert len(api.closed) == 1 and set(api.closed) == set(api.handles)
        else:
            assert api.events == []
        assert startup.identity == expected
    (tmp_path / "platform-header.json").write_text(
        json.dumps(
            {
                "mode": mode,
                "pid": process.pid,
                "created": created,
                "parent": parent,
                "native_ticks": str(birth),
                "legacy_created": birth / 10_000_000 - 11_644_473_600,
                "calls": api.events,
                "query_closes": len(api.closed),
                "native_api": "substituted",
            }
        )
    )
