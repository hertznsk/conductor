"""One early relation snapshot; query bindings never confer cleanup authority."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from contextlib import ExitStack
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from typing import Final, Literal, TypedDict

import psutil
import pytest
from _pytest.capture import CaptureManager
from artifact_policy import UnsafeArtifact, environment_sanitizer
from process_identity import Identity
from smoke.long_protocol import PROCESS_CAP
from smoke.long_records import Startup, control_records
from smoke.support import ProcessProbe, stop_owned, wait_until

READINESS_SECONDS: Final = 10
SNAPSHOT_SECONDS: Final = 2


class Receipt(TypedDict):
    stage: Literal["early"]
    outcome: Literal["incomplete", "positive"]
    alias: bool | None
    nodes: list[tuple[str, int, str, int, bool, bool, bool | None]]
    edges: list[tuple[int, int, bool, bool, int]]


@dataclass(frozen=True, slots=True)
class Node:
    """Retain a query object, not a termination capability."""

    probe: ProcessProbe
    parent: int

    def live(self) -> bool:
        fresh = psutil.Process(self.probe.process.pid)
        return (
            fresh.create_time() == self.probe.created
            and fresh.ppid() == self.parent
            and self.probe.record("early")["status"] == "live"
        )


def query(pid: int, held: dict[int, Node], handles: ExitStack) -> Node:
    """Open at most one query/synchronize handle for a directly observed PID."""
    if pid in held:
        return held[pid]
    if len(held) >= 6:
        raise UnsafeArtifact("identity-cap")
    probe = ProcessProbe.bind(psutil.Process(pid))
    handles.callback(probe.close)
    if sys.platform == "win32":
        if probe.native is None:
            raise UnsafeArtifact("native-unavailable")
        if (
            probe.native.pid != pid
            or probe.native.ticks / 10_000_000 - 11_644_473_600 != probe.created
        ):
            raise UnsafeArtifact("native-birth")
    node = Node(probe, psutil.Process(pid).ppid())
    held[pid] = node
    if not node.live():
        raise UnsafeArtifact("query-not-live")
    return node


def edge(child: Node, parent: Node) -> bool:
    """Bind the creator PID to a live retained creation identity without adoption."""
    return (
        child.parent == parent.probe.process.pid
        and parent.live()
        and child.live()
        and child.probe.created >= parent.probe.created
    )


def snapshot(root: Node, starts: list[Startup], handles: ExitStack) -> Receipt:
    """Prove only R0/C and up to one immediate intermediate per worker."""
    held = {root.probe.process.pid: root}
    receipt = Receipt(stage="early", outcome="incomplete", alias=None, nodes=[], edges=[])
    try:
        if sorted(s.role for s in starts) != ["controller", "gw0", "gw1"]:
            raise UnsafeArtifact("startup-roles")
        if len({s.pid for s in starts}) != 3:
            raise UnsafeArtifact("startup-alias")
        nodes = {}
        for start in starts:
            node = query(start.pid, held, handles)
            if (
                node.probe.created != start.created
                or node.probe.key != start.identity
                or node.parent != start.parent
            ):
                raise UnsafeArtifact("startup-binding")
            nodes[start.role] = node
        controller = nodes["controller"]
        anchors = {root.probe.process.pid: root, controller.probe.process.pid: controller}
        receipt["alias"] = controller is root
        required = []
        if controller is not root:
            required.append((controller, root))
        for role in ("gw0", "gw1"):
            worker = nodes[role]
            parent = query(worker.parent, held, handles)
            required.append((worker, parent))
            if parent.probe.process.pid not in anchors:
                anchor = anchors.get(parent.parent)
                if anchor is None:
                    raise UnsafeArtifact("foreign-parent")
                required.append((parent, anchor))
        for child, parent in required:
            known, live = child.live(), parent.live()
            proved = known and live and edge(child, parent)
            receipt["edges"].append(
                (child.probe.process.pid, parent.probe.process.pid, known, live, int(proved))
            )
        if required and all(row[-1] == 1 for row in receipt["edges"]):
            receipt["outcome"] = "positive"
    except (OSError, psutil.Error, UnsafeArtifact):
        receipt["outcome"] = "incomplete"
    finally:
        for pid, node in held.items():
            try:
                live = node.live()
            except (OSError, psutil.Error):
                live = False
            start = next((s for s in starts if s.pid == pid), None)
            matched = start is None or (
                start.created == node.probe.created and start.identity == node.probe.key
            )
            role = (
                start.role
                if start is not None and start.role in ("controller", "gw0", "gw1")
                else "P"
            )
            receipt["nodes"].append(
                (
                    "R0" if node is root else role,
                    pid,
                    node.probe.key.partition(":")[2],
                    node.parent,
                    matched,
                    live,
                    None if start is None else start.parent == node.parent,
                )
            )
            if not live or not matched:
                receipt["outcome"] = "incomplete"
    return receipt


def tiny_body() -> None:
    """Hold through the shared readiness/snapshot window, even if the observer disappears."""
    root = Path(os.environ["PR629_RELATIONS_DIR"])
    deadline = float(os.environ["PR629_RELATIONS_EXPIRY"])
    (root / (os.environ["PYTEST_XDIST_WORKER"] + ".ready")).touch()
    wait_until(lambda: (root / "release").exists() or time.monotonic() >= deadline, deadline + 1)


def test_early_launch_relations(tmp_path: Path, request: pytest.FixtureRequest) -> None:
    # Requirement: prove real early native creator edges without adopting query-only nodes.
    project, private = tmp_path / "project", tmp_path / "startup"
    project.mkdir()
    private.mkdir()
    for name in ("a", "b"):
        (project / f"test_{name}.py").write_text(
            "from smoke.test_launch_relations import tiny_body\n"
            "def test_short():"
            "\n    # Requirement: hold this worker only until snapshot or its finite deadline.\n"
            "    tiny_body()\n",
            encoding="ascii",
        )
    for name in ("artifacts", "home", "temp"):
        (tmp_path / name).mkdir(exist_ok=True)
    env = {
        **os.environ,
        "PR629_RELATIONS_DIR": str(tmp_path),
        "PR629_LONG_PROBE_DIR": str(private),
        "PR629_DIAG_DIR": str(tmp_path / "artifacts"),
    }
    for key in ("HOME", "USERPROFILE", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME"):
        env[key] = str(tmp_path / "home")
    for key in ("TMP", "TEMP", "TMPDIR"):
        env[key] = str(tmp_path / "temp")
    for key in ("GITHUB_ENV", "GITHUB_OUTPUT"):
        env[key] = str(tmp_path / key.lower())
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-p",
        "pr629_diag",
        "-p",
        "smoke.long_probe",
        "-p",
        "no:cacheprovider",
        "-n",
        "2",
        "--dist",
        "loadfile",
        "-o",
        "faulthandler_timeout=0",
        "-q",
        "test_a.py",
        "test_b.py",
    ]
    receipt = Receipt(stage="early", outcome="incomplete", alias=None, nodes=[], edges=[])
    with ExitStack() as handles:
        expiry = time.monotonic() + READINESS_SECONDS + SNAPSHOT_SECONDS
        env["PR629_RELATIONS_EXPIRY"] = str(expiry)
        child = subprocess.Popen(
            command, cwd=project, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        try:
            identity = Identity.child(child)
            handles.callback(identity.close)
            root = Node(
                ProcessProbe(psutil.Process(child.pid), identity.created, identity.native),
                os.getpid(),
            )
            wait_until(
                lambda: all((tmp_path / f"gw{i}.ready").exists() for i in range(2)),
                expiry - SNAPSHOT_SECONDS,
            )
            starts = []
            for path in islice(private.glob("*.jsonl"), 4):
                with path.open("rb") as stream:
                    line = stream.readline(PROCESS_CAP + 1)
                starts.append(control_records(line, environment_sanitizer()).startup)
            snapshot_end = min(expiry, time.monotonic() + SNAPSHOT_SECONDS)
            receipt = snapshot(root, starts, handles)
            if time.monotonic() >= snapshot_end:
                receipt["outcome"] = "incomplete"
        except (OSError, psutil.Error, UnsafeArtifact, AssertionError):
            receipt["outcome"] = "incomplete"
        finally:
            try:
                # Separate from the unchanged general SafeNote emitter; emit before release.
                capture = request.config.pluginmanager.getplugin("capturemanager")
                assert isinstance(capture, CaptureManager)
                payload = "PR629_RELATIONS " + json.dumps(receipt, separators=(",", ":"))
                assert payload.isascii() and len(payload.encode("ascii")) + 1 <= 2048
                with capture.global_and_fixture_disabled():
                    print(payload, file=sys.stderr, flush=True)
            finally:
                # Only the independently owned Popen root can be signalled.
                deadline = time.monotonic() + 3
                try:
                    (tmp_path / "release").touch()
                    root_code = child.wait(timeout=2)
                finally:
                    if child.returncode is None:
                        receipt["outcome"] = "incomplete"
                        stop_owned([child], deadline)
                        root_code = child.returncode
    if receipt["outcome"] != "positive" or root_code != 0:
        pytest.fail("Early launch relations incomplete.", pytrace=False)
