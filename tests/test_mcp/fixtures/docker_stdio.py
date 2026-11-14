"""Executable Docker stand-in with a separate, environment-isolated MCP peer.

Run through the temporary docker/docker.cmd launcher made by test_docker_transport.
Control commands reuse the existing fake daemon; only ``run`` owns stdio.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from pydantic import BaseModel, ConfigDict

sys.dont_write_bytecode = True


class PeerReceipt(BaseModel):
    """The server's independent observation of its own process."""

    model_config = ConfigDict(frozen=True)
    pid: int
    env: dict[str, str]
    called: bool
    closed: bool


class LaunchReceipt(BaseModel):
    """The fake CLI's observation of delivery and the joined peer."""

    model_config = ConfigDict(frozen=True)
    pid: int
    child_pid: int
    env: dict[str, str]
    argv: list[str]
    env_file: str
    payload: dict[str, str]
    mode: int
    joined: bool
    exit_code: int


def peer(receipt: Path) -> int:
    """Record the actual server environment and acknowledge a real tool request."""
    if os.environ.get("PEER_FAILURE", "").startswith("diagnostic-"):
        from diagnostic_stdio import diagnostic_peer

        return diagnostic_peer(receipt)
    snapshot = {"pid": os.getpid(), "env": dict(os.environ), "called": False, "closed": False}
    receipt.write_text(json.dumps(snapshot), encoding="utf-8")
    if os.environ.get("PEER_INITIALIZE_FILE"):
        # This is a disk-backed daemon model, not evidence of a native Docker mount.
        request = json.loads(sys.stdin.buffer.readline())
        assert request["method"] == "initialize"
        snapshot["initialize_seen"] = True
        workspace = Path(os.environ["PEER_WORKSPACE"])
        (workspace / os.environ["PEER_INITIALIZE_FILE"]).write_bytes(b"initialize-mutated\n")
    if os.environ.get("PEER_FAILURE") == "startup":
        snapshot["closed"] = True
        receipt.write_text(json.dumps(snapshot), encoding="utf-8")
        return 23

    from mcp.server.fastmcp import FastMCP

    server = FastMCP("environment-witness")

    @server.tool()
    def receive() -> str:
        """Acknowledge delivery without returning secret values through MCP."""
        snapshot["called"] = True
        receipt.write_text(json.dumps(snapshot), encoding="utf-8")
        if os.environ.get("PEER_FAILURE") == "transport":
            snapshot["closed"] = True
            receipt.write_text(json.dumps(snapshot), encoding="utf-8")
            os._exit(24)
        if os.environ.get("PEER_FAILURE") == "call":
            raise RuntimeError("fixture request rejected")
        return "payload received"

    try:
        server.run(transport="stdio")
    finally:
        snapshot["closed"] = True
        receipt.write_text(json.dumps(snapshot), encoding="utf-8")
    return 0


def main() -> int:
    """Keep Docker control traffic out of the SDK's protocol channel."""
    argv = sys.argv[1:]
    if argv[0] == "--peer":
        return peer(Path(argv[1]))
    helper = Path(__file__).resolve().parents[2] / "test_execution" / "docker_fake.py"
    control = subprocess.run(
        [sys.executable, str(helper), *argv],
        input=b"",
        capture_output=True,
        timeout=10,
        check=False,
    )
    if argv[0] != "run" or control.returncode:
        sys.stdout.buffer.write(control.stdout)
        sys.stderr.buffer.write(control.stderr)
        return control.returncode

    env_file = Path(argv[argv.index("--env-file") + 1])
    payload = dict(line.split("=", 1) for line in env_file.read_text(encoding="utf-8").splitlines())
    if payload.get("PEER_INITIALIZE_FILE"):
        state = json.loads(Path(os.environ["FAKE_DOCKER_STATE"]).read_text())
        name = argv[argv.index("--name") + 1]
        payload["PEER_WORKSPACE"] = str(
            Path(os.environ["FAKE_DOCKER_WORKSPACE_ROOT"]) / state["containers"][name]["Volume"]
        )
    receipt = Path(os.environ["MCP_PEER_RECEIPT"]).with_name(
        argv[argv.index("--name") + 1] + ".json"
    )
    launcher = receipt.with_suffix(".launcher.json")
    with subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "--peer", str(receipt)],
        env=payload,
    ) as child:
        launch = {
            "pid": os.getpid(),
            "child_pid": child.pid,
            "env": dict(os.environ),
            "argv": argv,
            "env_file": str(env_file),
            "payload": payload,
            "mode": env_file.stat().st_mode & 0o777,
            "joined": False,
        }
        launcher.write_text(json.dumps(launch), encoding="utf-8")
        try:
            code = child.wait(timeout=20)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
            raise
        launch["joined"] = True
        launch["exit_code"] = code
        launcher.write_text(json.dumps(launch), encoding="utf-8")
        return code


if __name__ == "__main__":
    raise SystemExit(main())
