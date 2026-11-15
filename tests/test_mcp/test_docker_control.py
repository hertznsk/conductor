"""Native contracts for the synthetic Docker control-command bootstrap."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import Final

import psutil
import pytest

from tests.test_mcp.fixtures.docker_realm import _PEER, _Realm, create_realm

_ENTRY: Final = """
import json, os, runpy, sys
from pathlib import Path
script = sys.argv.pop(1)
receipt = Path(sys.argv.pop(1))
sys.argv[0] = script
receipt.write_text(json.dumps({"pid": os.getpid()}))
try:
    runpy.run_path(script, run_name="__main__")
finally:
    receipt.write_text(json.dumps({
        "pid": os.getpid(),
        "peer_imports": [name for name in ("pydantic", "psutil", "mcp") if name in sys.modules],
    }))
"""
_NL: Final = os.linesep.encode()


@pytest.fixture
def realm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _Realm:
    return create_realm(tmp_path, monkeypatch)


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (("image", "inspect", "peer:image"), (0, b"{}" + _NL, b"")),
        (
            ("volume", "create", "--label", "key=literal & $HOME", "volume with spaces"),
            (0, b"volume with spaces" + _NL, b""),
        ),
        (("inspect", "missing container"), (1, b"", b"no such container: missing container" + _NL)),
        (
            ("unsupported", "literal & $HOME"),
            (2, b"", b"unsupported fake docker argv: ['unsupported', 'literal & $HOME']" + _NL),
        ),
    ],
)
def test_control_preserves_argv_environment_empty_stdin_and_result(
    realm: _Realm, argv: tuple[str, ...], expected: tuple[int, bytes, bytes]
) -> None:
    # Requirement: real control execution retains exact delivery and success/failure bytes.
    environment = {**realm.backend._cli_env, "CONTROL_WITNESS": "literal & $HOME \u03bb"}
    result = subprocess.run(
        [realm.backend._docker_binary, *argv],
        input=b"must not reach the daemon\x00\n",
        capture_output=True,
        env=environment,
        timeout=15,
        check=False,
    )
    assert (result.returncode, result.stdout, result.stderr) == expected
    record = json.loads((realm.root / "docker.jsonl").read_text())
    assert record["argv"] == list(argv) and record["stdin"] == ""
    assert record["env"] == environment
    if argv[:2] == ("volume", "create"):
        state = json.loads((realm.root / "state.json").read_text())
        assert state["volumes"] == {"volume with spaces": {"key": "literal & $HOME"}}


def test_control_uses_outer_interpreter_without_peer_imports(realm: _Realm) -> None:
    # Requirement: the actual daemon operation shares the outer CLI process, without SDK imports.
    receipt = realm.root / "outer.json"
    with socket.create_server(("127.0.0.1", 0)) as listener:
        listener.settimeout(5)
        environment = {
            **realm.backend._cli_env,
            "FAKE_DOCKER_DELAY_COMMAND": "image inspect",
            "FAKE_DOCKER_DELAY_READY_PORT": str(listener.getsockname()[1]),
        }
        with subprocess.Popen(
            [
                sys.executable,
                "-c",
                _ENTRY,
                str(_PEER),
                str(receipt),
                "image",
                "inspect",
                "peer:image",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        ) as child:
            try:
                connection, _address = listener.accept()
                with connection:
                    connection.settimeout(5)
                    with connection.makefile("rb") as stream:
                        identity = stream.readline().split()
                    daemon_pid = int(identity[0])
                    outer_pid = json.loads(receipt.read_text())["pid"]
                    connection.sendall(b"continue")
                out, err = child.communicate(input=b"ignored\n", timeout=15)
            except (OSError, subprocess.TimeoutExpired):
                child.kill()
                child.communicate(timeout=5)
                raise
        assert child.returncode == 0 and (out, err) == (b"{}" + _NL, b"")
    snapshot = json.loads(receipt.read_text())
    assert daemon_pid == outer_pid == snapshot["pid"]
    assert snapshot["peer_imports"] == []
    print({"outer_pid": outer_pid, "daemon_pid": daemon_pid, "joined": True})


async def test_control_cancellation_joins_native_owner_and_closes_pipe(realm: _Realm) -> None:
    # Requirement: backend cancellation reaches the real held control owner and drains its pipes.
    loop = asyncio.get_running_loop()
    with socket.create_server(("127.0.0.1", 0)) as listener:
        listener.setblocking(False)
        realm.backend._cli_env.update(
            FAKE_DOCKER_DELAY_COMMAND="image inspect",
            FAKE_DOCKER_DELAY_READY_PORT=str(listener.getsockname()[1]),
        )
        opening = asyncio.create_task(realm.backend._run_docker(("image", "inspect", "peer:image")))
        try:
            connection, _address = await asyncio.wait_for(loop.sock_accept(listener), 5)
            with connection:
                connection.setblocking(False)
                identity = b""
                while not identity.endswith(b"\n"):
                    chunk = await asyncio.wait_for(loop.sock_recv(connection, 4096), 5)
                    assert chunk
                    identity += chunk
                owner = psutil.Process(int(identity.split()[0]))
                opening.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await asyncio.wait_for(opening, 5)
                assert await asyncio.wait_for(loop.sock_recv(connection, 1), 5) == b""
                await asyncio.to_thread(owner.wait, timeout=5)
                assert not owner.is_running()
                print({"cancelled_owner": owner.pid, "terminal": True})
        finally:
            if not opening.done():
                opening.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await opening


def test_control_preserves_inner_ten_second_failure_bound(realm: _Realm) -> None:
    # Requirement: removing the helper process retains its failure status and bounded lifetime.
    environment = {
        **realm.backend._cli_env,
        "FAKE_DOCKER_DELAY_COMMAND": "image inspect",
        "FAKE_DOCKER_DELAY": "30",
    }
    result = subprocess.run(
        [sys.executable, str(_PEER), "image", "inspect", "peer:image"],
        input=b"ignored",
        capture_output=True,
        env=environment,
        timeout=15,
        check=False,
    )
    assert result.returncode == 1 and result.stdout == b""
    assert b"subprocess.TimeoutExpired" in result.stderr
    assert b"timed out after 10 seconds" in result.stderr
