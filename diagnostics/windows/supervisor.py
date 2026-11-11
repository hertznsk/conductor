#!/usr/bin/env python
# /// script
# requires-python = ">=3.13"
# dependencies = ["psutil>=6"]
# ///
# Run: uv run python <RUNNER_TEMP>/windows-preflight-diagnostic/supervisor.py
"""Inherit Actions output and observe anchored identities without external sampler helpers."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from types import FrameType

import psutil
from artifact_policy import LEVEL, MANDATORY_RECORDS, MIB, SCHEMA, environment_sanitizer
from diagnostic_sink import Sink
from process_identity import BindingError, Identity, State
from process_samples import Ledger
from pytest_command import pytest_argv


@dataclass(frozen=True, slots=True)
class Budget:
    start: float
    seconds: float = 1200
    grace: float = 30

    @property
    def end(self) -> float:
        return self.start + self.seconds - 5


def interrupted(signum: int, frame: FrameType | None) -> None:
    raise KeyboardInterrupt


def supervise(command: list[str], artifacts: Path, budget: Budget) -> int:
    """Popen alone owns the root outcome. Optional observer failures have their own receipts."""
    sanitizer = environment_sanitizer()
    events = Sink(artifacts / "supervisor.jsonl", sanitizer, MIB)
    samples = Sink(artifacts / "processes.jsonl", sanitizer)
    post = Sink(artifacts / "post-root.jsonl", sanitizer)
    environment = os.environ.copy()
    environment["PR629_DIAG_DIR"] = str(artifacts)
    environment["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(Path(__file__).parent), environment.get("PYTHONPATH", "")) if part
    )
    workers = int(command[command.index("-n") + 1]) if "-n" in command else 0
    events.emit(
        {
            "event": "expected",
            "level": LEVEL,
            "policy": SCHEMA,
            "expected_files": list(MANDATORY_RECORDS),
            "cov_xml": "--cov-report=xml" in command,
            "workers": workers,
            "argv": command,
            "step_start": budget.start,
            "step_budget": budget.seconds,
        }
    )
    events.emit(
        {
            "event": "scope",
            "name": "COPILOT_SKIP_CLI_DOWNLOAD",
            "status": environment.get("COPILOT_SKIP_CLI_DOWNLOAD", "unset"),
        }
    )
    events.emit(
        {
            "event": "scope",
            "name": "ANTHROPIC_API_KEY",
            "status": "present-not-recorded" if environment.get("ANTHROPIC_API_KEY") else "unset",
        }
    )
    ledger: Ledger | None = None
    root_code: int | None = None
    observer_failed = False
    cancelled = False
    lifecycle = False
    child: subprocess.Popen[bytes] | None = None
    try:
        # No PIPE, reader, tee, helper, or writable raw-output file is introduced here.
        child = subprocess.Popen(command, stdout=None, stderr=None, env=environment)
        events.emit({"event": "launch", "pid": child.pid, "argv": command})
        try:
            # This binding precedes the first poll/wait/reap on POSIX.
            identity = Identity.child(child)
            ledger = Ledger(identity, events)
            events.emit(identity.record("binding"))
        except BindingError as error:
            observer_failed = True
            events.emit(
                {"event": "observer.error", "status": error.state.value, "reason": error.reason}
            )
        except (OSError, psutil.Error, AttributeError):
            observer_failed = True
            events.emit(
                {
                    "event": "observer.error",
                    "status": "unavailable",
                    "reason": "initial-binding-unavailable",
                }
            )
        next_sample = time.monotonic()
        progress = next_sample
        progress_bytes = 0
        captures = 0
        observation_expired = False
        milestones = [1050, 1140]
        while (root_code := child.poll()) is None:
            now = time.monotonic()
            if now >= budget.end:
                if not observation_expired:
                    events.emit(
                        {"event": "observer.error", "reason": "observation-budget-exhausted"}
                    )
                    observation_expired = True
                observer_failed = True
                # The runner owns the unchanged Test limit; observation expiry is not a child code.
                try:
                    child.wait(timeout=0.1)
                except subprocess.TimeoutExpired:
                    continue
                continue
            try:
                if ledger is not None:
                    ledger.discover()
                    ledger.roles(artifacts)
                    ledger.observe(samples)
                size = sum(path.stat().st_size for path in artifacts.glob("*.phase.jsonl"))
                if size != progress_bytes:
                    progress, progress_bytes = now, size
                due = now >= next_sample
                if now - progress >= 60 and captures < 3:
                    events.emit({"event": "sample", "reason": "no-progress-60s"})
                    captures += 1
                    progress = now
                    due = True
                if milestones and now - budget.start >= milestones[0]:
                    events.emit({"event": "sample", "reason": f"milestone-{milestones.pop(0)}"})
                    due = True
                if due and ledger is not None:
                    ledger.sample(samples)
                    next_sample = now + 10
            except (OSError, psutil.Error):
                observer_failed = True
                events.emit({"event": "observer.error", "reason": "query-unavailable"})
            try:
                child.wait(timeout=min(0.25, max(0.001, budget.end - time.monotonic())))
            except subprocess.TimeoutExpired:
                continue
        if root_code is not None:
            # Save outcome before optional final observation, including cancellation during grace.
            root_exit = time.monotonic()
            events.emit({"event": "root-exit", "exitcode": root_code, "observed_at": root_exit})
            deadline = min(root_exit + min(budget.grace, 30), budget.end)
            if ledger is not None:
                ledger.frozen = True
                ledger.root.state = State.EXITED
                ledger.root.first_exit = ledger.root.first_exit or root_exit
                ledger.roles(artifacts)
            post.emit(
                {
                    "event": "post.begin",
                    "root_code": root_code,
                    "observed_at": root_exit,
                    "deadline": deadline,
                    "known": len(ledger.known) if ledger is not None else 0,
                }
            )
            while ledger is not None and time.monotonic() < deadline:
                ledger.observe(samples)
                lifecycle = all(item.state == State.EXITED for item in ledger.known.values())
                if lifecycle or time.monotonic() >= deadline:
                    break
                time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    except KeyboardInterrupt:
        cancelled = True
        if root_code is None and child is not None:
            root_code = child.poll()
    except OSError:
        # A launch error occurs before a child exists. Never convert it into a test pass.
        observer_failed = True
        events.emit(
            {
                "event": "observer.error",
                "reason": "test-not-launched" if child is None else "root-outcome-unavailable",
            }
        )
    finally:
        if ledger is not None:
            if root_code is not None:
                ledger.root.state = State.EXITED
                ledger.root.first_exit = ledger.root.first_exit or time.monotonic()
            try:
                lifecycle = ledger.finish(post)
                observer_failed = observer_failed or ledger.failed
            except (OSError, psutil.Error):
                lifecycle = False
                observer_failed = True
                events.emit({"event": "observer.error", "reason": "final-observation-unavailable"})
        post.emit(
            {
                **(
                    ledger.cleanup()
                    if ledger is not None
                    else {
                        "close_errors_count": 0,
                        "close_errors_recorded": 0,
                        "close_error_evidence_complete": False,
                        "observer_cleanup_status": "unknown",
                    }
                ),
                "event": "post.end",
                "root_code": root_code,
                "complete": lifecycle,
                "interrupted": cancelled,
                "observation_detached": not lifecycle,
                "observer_failed": observer_failed,
                "reason": "proved-exited" if lifecycle else "observation-unconfirmed",
            }
        )
        events.emit(
            {
                **(
                    ledger.cleanup()
                    if ledger is not None
                    else {
                        "close_errors_count": 0,
                        "close_errors_recorded": 0,
                        "close_error_evidence_complete": False,
                        "observer_cleanup_status": "unknown",
                    }
                ),
                "event": "exit",
                "root_code": root_code,
                "interrupted": cancelled,
                "observer_end": time.monotonic(),
                "observer_failed": observer_failed,
                "complete": lifecycle,
                "observation_detached": not lifecycle,
            }
        )
        events.close()
        samples.close()
        post.close()
    return root_code if root_code is not None else (130 if cancelled else 124)


def main() -> int:
    artifacts = Path(os.environ["RUNNER_TEMP"]) / "windows-preflight-diagnostic" / "artifacts"
    signal.signal(signal.SIGTERM, interrupted)
    # The shell records T0 before invoking uv; retain that setup/launch interval in the budget.
    elapsed = max(0, time.time() - float(os.environ["DIAG_STEP_START"]))
    budget = Budget(time.monotonic() - elapsed)
    code = supervise(pytest_argv(os.environ["DIAG_WORKERS"]), artifacts, budget)
    if sys.platform == "win32":
        return code if code < 2**31 else code - 2**32
    return code if code >= 0 else 128 - code


if __name__ == "__main__":
    sys.exit(main())
