"""Query-only numeric observation. No subprocesses, external helpers or output transport."""

from __future__ import annotations

import json
from pathlib import Path

import psutil
from artifact_policy import Record
from diagnostic_sink import Sink
from process_identity import Identity, State


class Ledger:
    """Own anchored identities and observation history; freeze permanently at root exit."""

    def __init__(self, root: Identity) -> None:
        self.known: dict[str, Identity] = {root.key: root}
        self.root = root
        self.frozen = False
        self.failed = False
        self.cpu: dict[str, tuple[float, float]] = {}
        self.reported_exit: set[str] = set()

    def discover(self) -> None:
        if self.frozen:
            return
        parents = {item.pid: item for item in self.known.values() if item.observe() == State.LIVE}
        for process in psutil.process_iter(["pid", "ppid", "create_time"]):
            parent = parents.get(process.info["ppid"])
            if parent is None or process.pid in parents:
                continue
            if len(self.known) >= 65536:
                self.failed = True
                return
            try:
                candidate = Identity.descendant(process, parent)
                if candidate.key in self.known:
                    candidate.close()
                else:
                    self.known[candidate.key] = candidate
            except (OSError, psutil.Error):
                self.failed = True

    def observe(self, sink: Sink) -> None:
        for item in self.known.values():
            before = item.state
            state = item.observe()
            if state != before or item.first_exit is None or item.key not in self.reported_exit:
                sink.emit(item.record("observed"))
            if state == State.EXITED:
                self.reported_exit.add(item.key)
                try:
                    item.close()
                except OSError:
                    self.failed = True
            if state in (State.UNAVAILABLE, State.AMBIGUOUS, State.MISMATCH):
                self.failed = True

    def sample(self, sink: Sink) -> None:
        cpu = psutil.cpu_times()
        disk = psutil.disk_io_counters()
        sink.emit(
            {
                "event": "host",
                "cpu_percent": psutil.cpu_percent(),
                "cpu_user": cpu.user,
                "cpu_system": cpu.system,
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
                io = process.io_counters()
                threads = process.threads()
                omitted = max(0, len(threads) - 256)
                total_threads += min(len(threads), 256)
                if total_threads > 4096:
                    omitted = len(threads)
                    threads = []
                record: Record = {
                    **item.record("process"),
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
                }
                if psutil.WINDOWS:
                    record["handles"] = process.num_handles()
                if item.observe() == State.LIVE:
                    sink.emit(record)
                if omitted:
                    self.failed = True
            except (OSError, psutil.Error):
                self.failed = True
                sink.emit(
                    {
                        "event": "observer.error",
                        "identity": item.key,
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
                    self.failed = True
                    continue
                record = json.loads(first)
                item = self.known.get(record.get("identity"))
                role = record.get("worker")
                if (
                    item is not None
                    and isinstance(role, str)
                    and (role == "controller" or (role.startswith("gw") and role[2:].isdigit()))
                ):
                    item.role = role
            except (OSError, ValueError, TypeError, AttributeError):
                self.failed = True

    def finish(self, sink: Sink) -> bool:
        complete = True
        for item in self.known.values():
            sink.emit(item.record("observed"))
            complete = complete and item.state == State.EXITED
            try:
                item.close()
            except OSError:
                self.failed = True
        return complete
