"""Real actor OLD/NEW ownership and query survival, with explicitly substituted native ABI."""

import ctypes
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType

import psutil
import pytest
from artifact_policy import UnsafeArtifact
from smoke import long_ownership, long_process
from smoke.long_diagnostics import control_note
from smoke.long_records import Startup
from smoke.parent_ownership_probe import (
    ActorCase,
    Attempt,
    Binding,
    NativeBoundary,
    Proof,
    Stop,
    install_native,
)
from smoke.support import stop_owned, wait_until
from smoke.test_readiness_interrupt import resources

BASELINE = "0844956c6d2244e4618cc09b6916d8f661f224a4"


def os_status(process: psutil.Process) -> str:
    try:
        return "proved-exited" if process.status() == psutil.STATUS_ZOMBIE else "live"
    except psutil.NoSuchProcess:
        return "proved-exited"


def old_runtime() -> tuple[ModuleType, str]:
    """Execute the frozen original runtime, which has no dependency on the new owner."""
    argv = ["git", "show", f"{BASELINE}:diagnostics/windows/smoke/long_process.py"]
    content = subprocess.check_output(argv, env={**os.environ, "GIT_MASTER": "1"})
    module = ModuleType("old_long_process")
    exec(compile(content, "<frozen-D13-long_process>", "exec"), module.__dict__)
    return module, hashlib.sha256(content).hexdigest()


def exercise(root: Path, patch, case: ActorCase) -> Proof:
    """Measure actual source stop/close before separate QA rescue of retained query actors."""
    baseline = resources()
    variant, depth, promote, survive = case.variant, case.depth, case.promote, case.survive
    (root / "project").mkdir()
    patch.delenv("SMOKE_EXPORT_ROOT", raising=False)
    patch.setenv("PYTHONPATH", os.pathsep.join(sys.path))
    patch.setenv("QA_DEPTH", str(depth))
    for name, value in (("QA_PROMOTE", promote), ("QA_SURVIVE", survive), ("QA_NATIVE", depth > 0)):
        patch.setenv(name, "1") if value else patch.delenv(name, raising=False)
    boundary = NativeBoundary()
    source, old_sha = (long_process, None) if variant == "new" else old_runtime()
    roots: list[subprocess.Popen[bytes]] = []
    owners: list[long_ownership.CreatorBindings] = []
    stops: list[Stop] = []
    closes: list[int] = []
    attempts: list[Attempt] = []
    headers: dict[str, Startup] = {}
    real_spawn, real_stop = subprocess.Popen, stop_owned
    real_admit = long_ownership.CreatorBindings.admit
    real_parse = source.control_records
    real_close = long_ownership.ProcessProbe.close
    if depth:
        install_native(patch, boundary)

    def admitted(owner, first, context):
        if not owners:
            owners.append(owner)
        result = real_admit(owner, first, context)
        attempts.append({"pid": first.pid, "role": first.role, "refused": result is not None})
        if first.role == "gw0":
            (root / "worker.attempted").touch()
        return result

    def parsed(data, sanitizer):
        result = real_parse(data, sanitizer)
        if sys._getframe(1).f_locals["scan"] == "run":
            headers[result.startup.role] = result.startup
        return result

    def spawned(args, *, cwd, env, stdout):
        child = real_spawn(
            [
                sys.executable,
                "-m",
                "smoke.parent_ownership_probe",
                env["PR629_LONG_PROBE_DIR"],
                "0",
            ],
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=stdout,
        )
        roots.append(child)
        assert child.stdin is not None
        private = Path(env["PR629_LONG_PROBE_DIR"])
        # Prepare real committed startup IO before the short survivor control budget starts.
        wait_until(
            lambda: any(p.read_bytes().endswith(b"\n") for p in private.glob("*.jsonl")),
            time.monotonic() + 10,
        )
        released = False

        def wait(timeout=None):
            nonlocal released
            controller_ready = any(
                a["role"] == ("controller" if promote or not depth else "gw0") and not a["refused"]
                for a in attempts
            )
            if variant == "old":
                # Observe the actual post-capture map, not a grant inferred from parsing.
                observed = sys._getframe(1).f_locals
                if "gw0" in headers and observed.get("first_failure") is not None:
                    (root / "worker.attempted").touch()
                controller = headers.get("controller")
                controller_ready = controller is not None and controller.identity in observed.get(
                    "probes", {}
                )
            if not survive and not released and controller_ready:
                released = True
                (root / "release.json").write_text(
                    json.dumps({role: startup.pid for role, startup in headers.items()})
                )
                assert child.stdin is not None
                child.stdin.write(b"G")
                child.stdin.flush()
            return real_spawn.wait(child, timeout=timeout)

        patch.setattr(child, "wait", wait)
        return child

    def stopped(children, deadline, peers=()):
        stops.append(
            {"peers": [p.pid for p in peers], "at": time.monotonic(), "deadline": deadline}
        )
        real_stop(children, deadline, peers)

    def closed(probe):
        real_close(probe)
        closes.append(probe.process.pid)

    patch.setattr(subprocess, "Popen", spawned)
    patch.setattr(source, "stop_owned", stopped)
    patch.setattr(source, "control_records", parsed)
    patch.setattr(long_ownership.CreatorBindings, "admit", admitted)
    patch.setattr(long_ownership.ProcessProbe, "close", closed)
    primary = None
    row: Proof
    try:
        try:
            source.run_control(["actor", "-n", "1"], root, 0.2 if survive else 45)
        except (UnsafeArtifact, AssertionError, subprocess.TimeoutExpired) as error:
            primary = error
        retained: list[Binding] = [
            {
                "pid": n.probe.process.pid,
                "parent": n.parent,
                "key": n.probe.key,
                "created": n.probe.created,
                "kind": n.kind,
                "status": os_status(n.probe.process),
            }
            for owner in owners
            for n in owner.nodes.values()
        ]
        row = {
            "variant": variant,
            "depth": depth,
            "promote": promote,
            "survive": survive,
            "old_sha": old_sha,
            "attempts": attempts,
            "bindings": retained,
            "stops": stops,
            "closes": closes.copy(),
            "native_open": boundary.opened,
            "native_close_count": len(boundary.closed),
            "wait_ms": boundary.waits,
            "primary": type(primary).__name__,
            "note": control_note(primary) if primary else None,
            "native_abi": "substituted" if depth else "not-used",
            "resources": {"before": baseline, "after": []},
        }
    finally:
        # QA rescue happens only after the source's stop/status/close evidence above.
        (root / "rescue").touch()
        real_stop(roots, time.monotonic() + 3)
        for child in roots:
            assert child.stdin is not None
            child.stdin.close()
        for owner in owners:
            for node in owner.nodes.values():
                if node.probe.process.pid != roots[0].pid:
                    try:
                        node.probe.process.wait(timeout=5)
                    except psutil.NoSuchProcess:
                        continue
                    if sys.platform == "linux":
                        try:
                            os.waitpid(node.probe.process.pid, os.WNOHANG)
                        except ChildProcessError:
                            continue
    row["resources"] = {"before": baseline, "after": resources()}
    (root / "ownership-proof.json").write_text(json.dumps(row, indent=2))
    assert row["resources"]["before"] == row["resources"]["after"]
    return row


@pytest.fixture
def reap_orphans():
    """Keep test actors reapable even when the original root is deliberately stopped."""
    if sys.platform == "linux":
        libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int()
        assert libc.prctl(37, ctypes.byref(previous), 0, 0, 0) == 0
        assert libc.prctl(36, 1, 0, 0, 0) == 0
        yield
        assert libc.prctl(36, previous.value, 0, 0, 0) == 0
    else:
        yield


@pytest.mark.parametrize("variant", ["old", "new"])
def test_real_original_root_alias_old_new(tmp_path, monkeypatch, reap_orphans, variant):
    # Requirement: an original-root controller alias is admitted by its full self identity.
    row = exercise(tmp_path, monkeypatch, ActorCase(variant, 0, False, False))
    assert len(row["stops"]) == 1 and row["stops"][0]["peers"] == []
    assert row["note"] is not None
    assert "owner=" not in row["note"]
    if variant == "new":
        assert [a["role"] for a in row["attempts"]] == ["controller"]
        assert [n["kind"] for n in row["bindings"]] == ["root"]


@pytest.mark.parametrize(
    "variant,depth,promote",
    [("old", 2, True), ("new", 1, False), ("new", 2, True), ("new", 3, True)],
)
def test_real_worker_before_controller_and_exact_signal_membership(
    tmp_path, monkeypatch, reap_orphans, variant, depth, promote
):
    # Requirement: OLD refuses indirect W but admits direct C; NEW preserves W-first promotion.
    row = exercise(tmp_path, monkeypatch, ActorCase(variant, depth, promote, False))
    if variant == "old":
        assert row["note"] is not None
        assert row["old_sha"] is not None and "owner=run:parent-check:" in row["note"]
        release = json.loads((tmp_path / "release.json").read_bytes())
        assert row["stops"][0]["peers"] == [release["controller"]]
        assert release["gw0"] not in row["stops"][0]["peers"]
        return
    assert all(not a["refused"] for a in row["attempts"])
    assert [a["role"] for a in row["attempts"]] == (["gw0", "controller"] if promote else ["gw0"])
    sources = {n["pid"] for n in row["bindings"] if n["kind"] == "source"}
    assert set(row["stops"][0]["peers"]) == sources
    assert len(sources) == (2 if promote else 1)
    assert sorted(row["closes"]) == sorted(n["pid"] for n in row["bindings"])
    assert row["native_close_count"] == depth
    assert all(rights == 0x101000 and not inherit for _, rights, inherit in row["native_open"])


def test_real_query_survivor_has_no_signal_authority(tmp_path, monkeypatch, reap_orphans):
    # Requirement: a live query stays unsignalled until rescue and makes cleanup incomplete.
    row = exercise(tmp_path, monkeypatch, ActorCase("new", 2, False, True))
    queries = [n for n in row["bindings"] if n["kind"] == "query"]
    assert len(queries) == 1 and queries[0]["status"] == "live"
    assert queries[0]["pid"] not in row["stops"][0]["peers"]
    assert row["note"] is not None
    assert "cleanup=false error=cleanup-unconfirmed" in row["note"]
    assert row["primary"] == "TimeoutExpired"
    assert row["native_close_count"] == 2
    assert all(0 <= ms <= 3000 for ms in row["wait_ms"])
