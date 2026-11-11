"""Own one long control, its original deadline, early identities and aggregate cleanup."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from itertools import islice
from pathlib import Path

import psutil
from artifact_policy import UnsafeArtifact, environment_sanitizer
from smoke.long_export import publish
from smoke.long_manifest import ControlResult, Normal, Outcome, Timeout, Unknown
from smoke.long_protocol import CASE_PROCESSES, PROCESS_CAP
from smoke.long_records import control_records
from smoke.support import ProcessProbe, stop_owned


def run_control(
    command: list[str], root: Path, seconds: float = 45
) -> subprocess.CompletedProcess[bytes]:
    """Observe one command and clean only recorded owned identities, preserving primary failure."""
    workers = int(command[command.index("-n") + 1])
    private = root / "long-control-private"
    private.mkdir()
    destination = (
        Path(os.environ.get("SMOKE_EXPORT_ROOT", str(root / "long-export"))) / f"long-w{workers}"
    )
    env = {
        **os.environ,
        "PR629_DIAG_DIR": str(root / "artifacts"),
        "PR629_LONG_PROBE_DIR": str(private),
    }
    observed_command = [*command, "-p", "smoke.long_probe"]
    child: subprocess.Popen[bytes] | None = None
    probes: dict[str, ProcessProbe] = {}
    attempted: set[Path] = set()
    ownership: list[str] = []
    outcome: Outcome = Unknown()

    def capture() -> None:
        if child is None:
            return
        for path in islice(private.glob("*.jsonl"), CASE_PROCESSES + 1):
            if path in attempted:
                continue
            attempted.add(path)
            if len(attempted) > CASE_PROCESSES:
                ownership.append("ownership-count-cap")
                return
            try:
                with path.open("rb") as stream:
                    first_line = stream.readline(PROCESS_CAP + 1)
                first = control_records(first_line, environment_sanitizer()).startup
                pid, created, identity = first.pid, first.created, first.identity
                if identity in probes:
                    continue
                process = psutil.Process(pid)
                if process.create_time() != created or process.ppid() != child.pid:
                    raise UnsafeArtifact("ownership-mismatch")
                probe = ProcessProbe.bind(process)
                if probe.key != identity:
                    probe.close()
                    raise UnsafeArtifact("ownership-mismatch")
                probes[identity] = probe
            except psutil.NoSuchProcess:
                # A self-recorded identity whose PID is already absent is not a cleanup target.
                continue
            except (OSError, psutil.Error, UnsafeArtifact):
                ownership.append("ownership-unavailable")

    try:
        child = subprocess.Popen(
            observed_command, cwd=root / "project", env=env, stdout=subprocess.DEVNULL
        )
        end = time.monotonic() + seconds
        root_probe = ProcessProbe.bind(psutil.Process(child.pid))
        probes[root_probe.key] = root_probe
        while True:
            capture()
            remaining = end - time.monotonic()
            if remaining <= 0:
                outcome = Timeout()
                raise subprocess.TimeoutExpired(observed_command, seconds)
            try:
                normal = child.wait(timeout=min(0.05, remaining))
                outcome = Normal(normal)
                break
            except subprocess.TimeoutExpired:
                continue
        assert normal == 0, f"Nested long control exited with code {normal}."
        return subprocess.CompletedProcess(observed_command, normal)
    finally:
        primary = sys.exception()
        cleanup_errors: list[str] = []
        deadline = time.monotonic() + 3
        try:
            capture()
            if child is not None:
                stop_owned(
                    [child],
                    deadline,
                    [p.process for p in probes.values() if p.process.pid != child.pid],
                )
            for probe in probes.values():
                if probe.record("cleanup")["status"] != "proved-exited":
                    cleanup_errors.append("cleanup-unconfirmed")
        except (OSError, psutil.Error, AssertionError, UnsafeArtifact):
            cleanup_errors.append("cleanup-unavailable")
        finally:
            for probe in probes.values():
                try:
                    probe.close()
                except OSError:
                    cleanup_errors.append("cleanup-close-failed")
        complete = False
        publication_error: BaseException | None = None
        try:
            complete = publish(
                private,
                destination,
                ControlResult(
                    workers,
                    outcome,
                    cleanup_errors[0] if cleanup_errors else ownership[0] if ownership else None,
                ),
            )
        except (OSError, UnsafeArtifact, ValueError) as error:
            publication_error = error
        if publication_error is not None or not complete:
            if primary is not None:
                primary.add_note("Long control evidence is incomplete.")
            elif publication_error is not None:
                raise publication_error
            else:
                raise UnsafeArtifact("long-control-evidence-incomplete")
