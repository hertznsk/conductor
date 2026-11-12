"""Own one long control, its original deadline, early identities and aggregate cleanup."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from dataclasses import replace
from itertools import islice
from pathlib import Path

import psutil
from artifact_policy import UnsafeArtifact, environment_sanitizer
from smoke.long_diagnostics import OwnershipFailure, render_note
from smoke.long_export import checked_control, publish
from smoke.long_manifest import ControlResult, Normal, Outcome, Timeout, Unknown
from smoke.long_ownership import CreatorBindings
from smoke.long_protocol import CASE_PROCESSES, PROCESS_CAP
from smoke.long_records import control_records
from smoke.support import stop_owned


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
    owner: CreatorBindings | None = None
    slots: dict[Path, bytes | None] = {}
    overflow = False
    ownership: list[str] = []
    outcome: Outcome = Unknown()
    first_failure: OwnershipFailure | None = None
    further_failures = 0

    def capture(scan: str = "run") -> None:
        nonlocal first_failure, further_failures, overflow
        if child is None:
            return
        candidates = dict.fromkeys((*slots, *islice(private.glob("*.jsonl"), CASE_PROCESSES + 1)))
        for path in candidates:
            if path not in slots:
                if len(slots) == CASE_PROCESSES:
                    if not overflow:
                        ownership.append("ownership-count-cap")
                        overflow = True
                    continue
                slots[path] = b""
            prefix = slots[path]
            if prefix is None:
                continue
            stage, role = "open", "unknown"
            read_bytes, line_complete, native_bound = None, None, None
            try:
                with path.open("rb") as stream:
                    stage = "read"
                    first_line = stream.readline(PROCESS_CAP + 1)
                read_bytes, line_complete = len(first_line), first_line.endswith(b"\n")
                stage = "startup-parse"
                if read_bytes > PROCESS_CAP:
                    raise UnsafeArtifact("oversize")
                if not first_line.startswith(prefix):
                    raise UnsafeArtifact("startup-prefix-changed")
                if not line_complete:
                    if scan != "run" or time.monotonic() >= end or child.returncode is not None:
                        raise UnsafeArtifact("startup-not-bound-before-stop")
                    slots[path] = first_line
                    continue
                slots[path] = None
                first = control_records(first_line, environment_sanitizer()).startup
                role = first.role
                if scan != "run" or time.monotonic() >= end or child.returncode is not None:
                    raise UnsafeArtifact("startup-not-bound-before-stop")
                if first.role not in ("controller", *(f"gw{i}" for i in range(workers))):
                    raise UnsafeArtifact("ownership-mismatch")
                if owner is None:
                    raise UnsafeArtifact("startup-not-bound-before-stop")
                refusal = owner.admit(
                    first, OwnershipFailure(scan, stage, role, read_bytes, line_complete)
                )
                if refusal is not None:
                    code, failure = refusal
                    ownership.append(code)
                    if first_failure is None:
                        first_failure = failure
                    else:
                        further_failures = min(CASE_PROCESSES, further_failures + 1)
            except psutil.NoSuchProcess:
                slots[path] = None
                # A self-recorded identity whose PID is already absent is not a cleanup target.
                continue
            except (OSError, psutil.Error, UnsafeArtifact) as error:
                slots[path] = None
                ownership.append("ownership-unavailable")
                if first_failure is None:
                    first_failure = OwnershipFailure(
                        scan, stage, role, read_bytes, line_complete, native_bound
                    ).caused_by(error)
                else:
                    further_failures = min(CASE_PROCESSES, further_failures + 1)

    try:
        child = subprocess.Popen(
            observed_command, cwd=root / "project", env=env, stdout=subprocess.DEVNULL
        )
        end = time.monotonic() + seconds
        owner = CreatorBindings(child, end)
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
        deferred: KeyboardInterrupt | None = None
        cleanup_errors = owner.errors if owner is not None else []
        if owner is not None:
            owner.sealed = True
        deadline = time.monotonic() + 3
        try:
            if child is not None:
                stop_owned(
                    [child],
                    deadline,
                    [node.probe.process for node in owner.nodes.values() if node.kind == "source"]
                    if owner is not None
                    else [],
                )
        except (OSError, psutil.Error, AssertionError, UnsafeArtifact):
            cleanup_errors.append("cleanup-unavailable")
        finally:
            if owner is not None:
                try:
                    owner.finish(deadline)
                except KeyboardInterrupt as error:
                    if primary is None:
                        primary = deferred = error
                    else:
                        primary.add_note("Secondary KeyboardInterrupt during owned cleanup.")
        try:
            capture("final")
        except KeyboardInterrupt as error:
            ownership.append("ownership-unavailable")
            if primary is None:
                primary = deferred = error
            else:
                primary.add_note("Secondary KeyboardInterrupt during final startup observation.")
        except (OSError, psutil.Error, AssertionError, UnsafeArtifact):
            cleanup_errors.append("cleanup-unavailable")
        complete = False
        publication_error: BaseException | None = None
        result = ControlResult(
            workers,
            outcome,
            cleanup_errors[0] if cleanup_errors else ownership[0] if ownership else None,
        )
        try:
            complete = publish(private, destination, result)
        except (OSError, UnsafeArtifact, ValueError) as error:
            publication_error = error
        note = None
        detail = (
            replace(first_failure, additional=further_failures)
            if first_failure is not None
            else None
        )
        if primary is not None or publication_error is not None or not complete:
            view = None
            category = "publication-refused" if publication_error is not None else "checked"
            try:
                if publication_error is None:
                    view = checked_control(destination)
                note = render_note(result, view, category, ownership=detail)
            except (OSError, ValueError, TypeError, UnsafeArtifact):
                note = render_note(result, None, "summary-unavailable", ownership=detail)
            if primary is not None:
                primary.add_note(note)
        if publication_error is not None or not complete:
            if primary is not None:
                primary.add_note("Long control evidence is incomplete.")
            elif publication_error is not None:
                if note is not None:
                    publication_error.add_note(note)
                raise publication_error
            else:
                failure = UnsafeArtifact("long-control-evidence-incomplete")
                if note is not None:
                    failure.add_note(note)
                raise failure
        if deferred is not None:
            raise deferred
