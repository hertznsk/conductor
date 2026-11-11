"""Query-only numeric observation. No subprocesses, external helpers or output transport."""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import psutil
from artifact_policy import CLOSE_TYPES, Record
from diagnostic_sink import Sink
from process_identity import Identity, State


class Ledger:
    """Own anchored identities and observation history; freeze permanently at root exit."""

    def __init__(self, root: Identity, diagnostics: Sink) -> None:
        self.known: dict[str, Identity] = {root.key: root}
        self.root = root
        self.frozen = False
        self.failed = False
        self.cpu: dict[str, tuple[float, float]] = {}
        self.reported_exit: set[str] = set()
        self.diagnostics = diagnostics
        self.close_errors_count = 0
        self.close_errors_recorded = 0
        self.close_error_evidence_complete = True
        self.failed_closes: set[str] = set()
        self.reason_count = 0
        self.sample_id = 0

    def fail(self, reason: str, stage: str, item: Identity | None = None) -> None:
        self.failed = True
        self.reason_count += 1
        if self.reason_count > 256:
            self.diagnostics.fail("observer-reason-budget")
            return
        self.diagnostics.emit(
            {
                "event": "observer.error",
                "reason": reason,
                "stage": stage,
                "identity": item.key if item is not None else None,
                "pid": item.pid if item is not None else None,
            }
        )

    def close(self, item: Identity, stage: str) -> None:
        registered = self.known.get(item.key) is item
        if registered and item.key in self.failed_closes:
            return
        try:
            item.close()
        except OSError as error:
            if registered:
                self.failed_closes.add(item.key)
            self.close_errors_count += 1
            qualified = (
                registered
                and item.state == State.EXITED
                and item.first_exit is not None
                and math.isfinite(item.first_exit)
            )
            if not qualified:
                self.fail("unqualified-process-close-failed", stage, item)
            record: Record = {
                "event": "process.close_error",
                "identity": item.key,
                "pid": item.pid,
                "role": item.role,
                "status": item.state.value,
                "first_exit": item.first_exit,
                "stage": stage,
                "reason": "process-handle-close-failed",
                "exception_type": type(error).__name__
                if type(error).__name__ in CLOSE_TYPES
                else "OSError",
                "errno": error.errno,
                "winerror": getattr(error, "winerror", None),
            }
            if self.close_errors_count <= 256 and self.diagnostics.emit(record):
                self.close_errors_recorded += 1
            else:
                self.close_error_evidence_complete = False
                self.diagnostics.fail("close-error-evidence-incomplete")

    def cleanup(self) -> Record:
        return {
            "close_errors_count": self.close_errors_count,
            "close_errors_recorded": self.close_errors_recorded,
            "close_error_evidence_complete": self.close_error_evidence_complete,
            "observer_cleanup_status": (
                "unknown"
                if not self.close_error_evidence_complete
                else "close-error"
                if self.close_errors_count
                else "no-recorded-errors"
            ),
        }

    def discover(self) -> None:
        if self.frozen:
            return
        parents = {item.pid: item for item in self.known.values() if item.observe() == State.LIVE}
        for process in psutil.process_iter(["pid", "ppid", "create_time"]):
            parent = parents.get(process.info["ppid"])
            if parent is None or process.pid in parents:
                continue
            if len(self.known) >= 65536:
                self.fail("identity-budget", "discover", parent)
                return
            try:
                candidate = Identity.descendant(process, parent)
                if candidate.key in self.known:
                    self.close(candidate, "discover-duplicate")
                else:
                    self.known[candidate.key] = candidate
            except (OSError, psutil.Error):
                self.fail("descendant-binding-unavailable", "discover", parent)

    def observe(self, sink: Sink) -> None:
        for item in self.known.values():
            before = item.state
            state = item.observe()
            if state != before or item.first_exit is None or item.key not in self.reported_exit:
                sink.emit(item.record("observed"))
            if state == State.EXITED:
                self.reported_exit.add(item.key)
                self.close(item, "observe-exited")
            if state in (State.UNAVAILABLE, State.AMBIGUOUS, State.MISMATCH):
                self.fail("physical-observation-unavailable", "observe", item)

    def sample(self, sink: Sink) -> None:
        self.sample_id += 1
        cpu = psutil.cpu_times()
        disk = psutil.disk_io_counters()
        sink.emit(
            {
                "event": "host",
                "sample_id": self.sample_id,
                "cpu_percent": psutil.cpu_percent(),
                "cpu_user": cpu.user,
                "cpu_system": cpu.system,
                "cpu_total": sum(cpu) - getattr(cpu, "guest", 0) - getattr(cpu, "guest_nice", 0),
                "cpu_idle": cpu.idle + getattr(cpu, "iowait", 0),
                "memory_total": psutil.virtual_memory().total,
                "memory_available": psutil.virtual_memory().available,
                "read_bytes": disk.read_bytes if disk is not None else None,
                "write_bytes": disk.write_bytes if disk is not None else None,
            }
        )
        total_threads = 0
        for item in self.known.values():
            if item.observe() != State.LIVE:
                continue
            try:
                process = psutil.Process(item.pid)
                cpu = process.cpu_times()
                previous = self.cpu.get(item.key, (cpu.user, cpu.system))
                self.cpu[item.key] = (cpu.user, cpu.system)
                memory = process.memory_info()
                if not hasattr(process, "io_counters") or not hasattr(process, "threads"):
                    self.fail("numeric-api-unavailable", "sample", item)
                    continue
                io = process.io_counters()
                threads = process.threads()
                omitted = max(0, len(threads) - 256)
                total_threads += min(len(threads), 256)
                if total_threads > 4096:
                    omitted = len(threads)
                    threads = []
                record: Record = {
                    **item.record("process"),
                    "sample_id": self.sample_id,
                    "cpu_user": cpu.user,
                    "cpu_system": cpu.system,
                    "cpu_user_delta": cpu.user - previous[0],
                    "cpu_system_delta": cpu.system - previous[1],
                    "rss": memory.rss,
                    "vms": memory.vms,
                    "read_bytes": io.read_bytes,
                    "write_bytes": io.write_bytes,
                    "thread_ids": [thread.id for thread in threads[:256]],
                    "thread_count": process.num_threads(),
                    "omitted": omitted,
                    "affinity": process.cpu_affinity()[:256]
                    if hasattr(process, "cpu_affinity")
                    else [],
                }
                if sys.platform == "win32" and hasattr(process, "num_handles"):
                    record["handles"] = process.num_handles()
                if item.observe() == State.LIVE:
                    sink.emit(record)
                else:
                    self.fail("numeric-identity-unavailable", "sample", item)
                if omitted:
                    self.fail("thread-budget", "sample", item)
            except (OSError, psutil.Error):
                self.fail("numeric-query-unavailable", "sample", item)
                sink.emit(
                    {
                        "event": "observer.error",
                        "identity": item.key,
                        "role": item.role,
                        "stage": "sample",
                        "sample_id": self.sample_id,
                        "reason": "numeric-query-unavailable",
                    }
                )

    def roles(self, artifacts: Path) -> None:
        # Read only the bounded first record, never the growing phase log.
        for path in artifacts.glob("*.phase.jsonl"):
            try:
                with path.open("rb") as stream:
                    first = stream.readline(65537)
                if len(first) > 65536 or not first.endswith(b"\n"):
                    self.fail("role-receipt-size-or-tail", "roles")
                    continue
                record = json.loads(first)
                item = self.known.get(record.get("identity"))
                role = record.get("worker")
                if item is None and not self.frozen:
                    continue
                if (
                    item is not None
                    and isinstance(role, str)
                    and (role == "controller" or (role.startswith("gw") and role[2:].isdigit()))
                ):
                    item.role = role
                else:
                    self.fail("role-binding-unavailable", "roles", item)
            except (OSError, ValueError, TypeError, AttributeError):
                self.fail("role-receipt-unreadable", "roles")

    def finish(self, sink: Sink) -> bool:
        complete = True
        for item in self.known.values():
            sink.emit(item.record("observed"))
            complete = complete and item.state == State.EXITED
            self.close(item, "finish")
        return complete
