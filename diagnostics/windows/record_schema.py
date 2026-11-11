"""Finite field and event vocabulary for service-owned structured records."""

from dataclasses import dataclass, field
from typing import Final, TypedDict


class OpenPhase(TypedDict):
    item_index: int
    phase: str
    begin: float
    observed_until: float | None


@dataclass(slots=True)
class TimingWorker:
    """Accumulate bounded timing reductions for one clock domain."""

    clock: str
    phase_wall_seconds: dict[str, float] = field(default_factory=dict)
    phase_intervals: dict[str, list[float]] = field(default_factory=dict)
    reported_duration_sum: dict[str, float] = field(default_factory=dict)
    completed_outcomes: dict[str, int] = field(default_factory=dict)
    open_phases: list[OpenPhase] = field(default_factory=list)
    last_active_item_index: int | None = None


STRING_FIELDS: Final = frozenset(
    {
        "event",
        "utc",
        "worker",
        "nodeid",
        "phase",
        "outcome",
        "name",
        "stage",
        "reason",
        "path",
        "version",
        "package",
        "sha",
        "tree",
        "service_sha",
        "checkout_head",
        "image_os",
        "image_version",
        "python",
        "executable",
        "marker",
        "dist",
        "mode",
        "identity",
        "parent_identity",
        "role",
        "status",
        "scope",
        "level",
        "kind",
        "run_url",
        "run_id",
        "run_attempt",
        "job_key",
        "matrix_check",
        "test_step_name",
        "ticks",
        "service_head",
        "lock_hash",
        "error",
        "policy",
        "label",
        "exception_type",
        "observer_cleanup_status",
    }
)

INTEGER_FIELDS: Final = frozenset(
    {
        "sequence",
        "pid",
        "parent",
        "ident",
        "native_id",
        "exitcode",
        "workers",
        "numprocesses",
        "thread_count",
        "handles",
        "omitted",
        "expected",
        "bytes",
        "source_bytes",
        "root_code",
        "stack_fd",
        "durations",
        "verbosity",
        "rss",
        "vms",
        "cpu_count",
        "process_cpu_count",
        "memory_total",
        "memory_available",
        "disk_total",
        "disk_free",
        "read_bytes",
        "write_bytes",
        "collected",
        "total_outcomes",
        "known",
        "exited",
        "live",
        "unavailable",
        "item_index",
        "sample_id",
        "errno",
        "winerror",
        "close_errors_count",
        "close_errors_recorded",
    }
)

NUMBER_FIELDS: Final = frozenset(
    {
        "monotonic",
        "created",
        "last_live",
        "first_exit",
        "deadline",
        "observed_at",
        "observer_end",
        "cpu_user",
        "cpu_system",
        "cpu_user_delta",
        "cpu_system_delta",
        "cpu_percent",
        "step_start",
        "step_budget",
        "grace",
        "durations_min",
        "duration",
        "cpu_total",
        "cpu_idle",
    }
)

BOOL_FIELDS: Final = frozenset(
    {
        "daemon",
        "failed",
        "stack_armed",
        "interrupted",
        "complete",
        "cacheprovider",
        "cov_xml",
        "cov_term_missing",
        "observation_detached",
        "faulthandler_zero",
        "uploaded",
        "observer_failed",
        "budget_exhausted",
        "close_error_evidence_complete",
    }
)

EVENTS: Final = frozenset(
    {
        "start",
        "configured",
        "collected",
        "thread",
        "setup.begin",
        "setup.end",
        "call.begin",
        "call.end",
        "teardown.begin",
        "teardown.end",
        "runtest.begin",
        "runtest.end",
        "report",
        "sessionfinish.begin",
        "sessionfinish.end",
        "unconfigure.begin",
        "unconfigure.end",
        "worker-down",
        "summary.begin",
        "summary.end",
        "stack-arm",
        "diagnostic.failure",
        "expected",
        "launch",
        "binding",
        "observer.error",
        "process.close_error",
        "process",
        "sample",
        "host",
        "root-exit",
        "post.begin",
        "observed",
        "post.end",
        "exit",
        "environment",
        "version",
        "service-file",
        "raw-channel",
        "scope",
        "step",
    }
)
