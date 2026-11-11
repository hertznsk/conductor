"""Bounded projections of pytest state; no process execution or publication."""

from __future__ import annotations

import os
import sys
import tempfile
from collections import Counter, deque
from pathlib import Path
from types import ModuleType

import psutil
import pytest
from artifact_policy import Record, environment_sanitizer
from diagnostic_sink import Sink
from smoke.long_protocol import (
    EXCEPTIONS,
    FAILURES,
    FILES,
    FUNCTIONS,
    PLUGINS,
    PROCESS_CAP,
    ROLES,
)
from smoke.support import ProcessProbe


class Probe:
    """Accumulate event counters; only checkpoints/milestones write, never a periodic sampler."""

    def __init__(self, directory: Path) -> None:
        role = os.environ.get("PYTEST_XDIST_WORKER", "controller")
        role = role if role in ROLES else "unknown"
        self.sink = Sink(
            directory / f"{os.getpid()}-{role}.jsonl", environment_sanitizer(), PROCESS_CAP
        )
        self.base: Record = {
            "pid": os.getpid(),
            "parent": os.getppid(),
            "worker": role,
            "role": role,
            "scope": "long-control",
        }
        self.counts: Counter[tuple[str, str]] = Counter()
        self.collected: int | None = None
        self.errors = 0
        probe: ProcessProbe | None = None
        try:
            probe = ProcessProbe.bind(psutil.Process())
            if sys.platform == "win32" and probe.native is None:
                self.sink.fail("identity-unavailable")
                return
            self.base.update(identity=probe.key, created=probe.created)
            self.emit(
                {"event": "observed", "stage": "startup", "kind": "process", "status": "live"}
            )
        except (OSError, psutil.Error):
            self.sink.fail("identity-unavailable")
        finally:
            if probe is not None:
                try:
                    probe.close()
                except OSError:
                    self.sink.fail("identity-close-unavailable")

    def emit(self, record: Record) -> None:
        self.sink.emit({**self.base, **record})

    def snapshot(self, stage: str) -> None:
        module = sys.modules.get("pr629_diag")
        main = getattr(getattr(module, "OBSERVATION", None), "sink", None)
        # expected is the main Sink's next sequence; own sequence always belongs to this sidecar.
        self.emit(
            {
                "event": "observed",
                "kind": "main-sink",
                "stage": stage,
                "name": "main-sink",
                "expected": main.sequence if isinstance(main, Sink) else None,
                "bytes": main.bytes if isinstance(main, Sink) else None,
                "error": (main.failure if main.failure in FAILURES else "unknown")
                if isinstance(main, Sink) and main.failure is not None
                else None
                if isinstance(main, Sink)
                else "main-sink-unavailable",
                "status": ("available" if main.failure is None else "failed")
                if isinstance(main, Sink)
                else "unknown",
                "collected": self.collected,
                "total_outcomes": sum(
                    n for (phase, _), n in self.counts.items() if phase == "teardown"
                ),
                "omitted": max(0, self.errors - 8),
            }
        )
        for (phase, outcome), count in sorted(self.counts.items()):
            self.emit(
                {
                    "event": "scope",
                    "kind": "outcome-count",
                    "stage": stage,
                    "phase": phase,
                    "outcome": outcome,
                    "total_outcomes": count,
                }
            )

    def configuration(self, config: pytest.Config) -> None:
        cwd = Path.cwd().resolve()
        for name, path in (
            ("rootpath", config.rootpath),
            ("inipath", config.inipath),
            ("confcutdir", config.getoption("confcutdir")),
        ):
            try:
                resolved = Path(path).resolve() if path is not None else None
                status = (
                    "none"
                    if resolved is None
                    else "workspace"
                    if resolved == cwd
                    else "workspace-child"
                    if resolved.is_relative_to(cwd)
                    else "ancestor"
                    if cwd.is_relative_to(resolved)
                    else "outside"
                )
            except (OSError, ValueError):
                status = "unknown"
            self.emit(
                {
                    "event": "scope",
                    "kind": "configuration",
                    "stage": "config",
                    "name": name,
                    "status": status,
                }
            )
        root = self.sink.path.parent.parent.resolve()
        for name, path in (
            ("home-contained", Path.home()),
            ("temp-contained", Path(tempfile.gettempdir())),
        ):
            self.emit(
                {
                    "event": "scope",
                    "kind": "configuration",
                    "stage": "config",
                    "name": name,
                    "complete": path.resolve().is_relative_to(root),
                }
            )
        service = (Path(__file__).parents[1] / "conftest.py").resolve()
        present = False
        for plugin in config.pluginmanager.get_plugins():
            filename = getattr(plugin, "__file__", None)
            if isinstance(plugin, ModuleType) and isinstance(filename, str):
                present = present or Path(filename).resolve() == service
        for name, enabled in [
            ("service-conftest", present),
            *((name, config.pluginmanager.hasplugin(name)) for name in PLUGINS),
        ]:
            self.emit(
                {
                    "event": "scope",
                    "kind": "configuration",
                    "stage": "config",
                    "name": name,
                    "status": "present" if enabled else "absent",
                }
            )
        self.snapshot("config")

    def exception(self, error: BaseException | None, phase: str) -> None:
        self.errors += 1
        if self.errors > 8:
            return
        locations: deque[tuple[str, str, int | None]] = deque(maxlen=8)
        total = 0
        tb = error.__traceback__ if error is not None else None
        while tb is not None:
            total += 1
            basename = Path(tb.tb_frame.f_code.co_filename).name
            function = tb.tb_frame.f_code.co_name
            safe = basename in FILES and function in FUNCTIONS
            locations.append(
                (
                    basename if safe else "unknown",
                    function if safe else "unknown",
                    tb.tb_lineno if safe else None,
                )
            )
            tb = tb.tb_next
        kind = type(error).__name__ if error is not None else "unknown"
        errno = error.errno if isinstance(error, OSError) else None
        winerror = getattr(error, "winerror", None) if isinstance(error, OSError) else None
        self.emit(
            {
                "event": "observed",
                "stage": "error",
                "kind": "exception",
                "phase": phase,
                "known": self.errors,
                "exception_type": kind if kind in EXCEPTIONS else "unknown",
                "errno": errno if type(errno) is int else None,
                "winerror": winerror if type(winerror) is int else None,
                "omitted": max(0, total - 8),
            }
        )
        # ident is the one-based source line identifier, never an address or thread identifier here.
        for path, name, line in locations:
            self.emit(
                {
                    "event": "scope",
                    "stage": "error",
                    "kind": "frame",
                    "phase": phase,
                    "known": self.errors,
                    "path": path,
                    "name": name,
                    "ident": line,
                    "status": "unknown" if line is None else "known",
                }
            )
        self.snapshot("error")
