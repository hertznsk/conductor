"""Finite vocabulary for compact long-control receipts."""

from typing import Final

PROCESS_CAP: Final = 65536
CASE_PROCESSES: Final = 4  # At most eight process receipts across long-w1 and long-w2.
ROLES: Final = frozenset(("controller", "gw0", "gw1"))
STAGES: Final = frozenset(
    (
        "startup",
        "config",
        "collection",
        "checkpoint",
        "error",
        "collection-report",
        "sessionfinish.begin",
        "sessionfinish.end",
        "unconfigure.begin",
        "unconfigure.end",
        "worker-down",
        "summary.begin",
        "summary.end",
    )
)
FILES: Final = frozenset(
    (
        "test_long.py",
        "test_more.py",
        "test_probe.py",
        "conftest.py",
        "pr629_diag.py",
        "runner.py",
        "python.py",
        "fixtures.py",
        "main.py",
        "terminal.py",
        "remote.py",
        "dsession.py",
        "workermanage.py",
        "threading.py",
        "pathlib.py",
        "_local.py",
    )
)
FUNCTIONS: Final = frozenset(
    (
        "test_parameter",
        "test_following",
        "test_more",
        "test_probe",
        "isolated_paths",
        "pytest_runtest_call",
        "pytest_runtest_setup",
        "pytest_runtest_teardown",
        "pytest_fixture_setup",
        "pytest_pyfunc_call",
        "call_and_report",
        "call_runtest_hook",
        "runtest",
        "setup",
        "teardown",
        "execute",
        "__call__",
        "mkdir",
    )
)
PLUGINS: Final = ("pr629_diag", "xdist", "asyncio", "anyio", "pytest_cov", "smoke.long_probe")
NAMES: Final = (
    FUNCTIONS
    | frozenset(PLUGINS)
    | frozenset(
        (
            "main-sink",
            "rootpath",
            "inipath",
            "confcutdir",
            "home-contained",
            "temp-contained",
            "service-conftest",
            "isolated_paths-all",
            "controller",
            "gw0",
            "gw1",
            "unknown",
            "config-query",
        )
    )
)
EXCEPTIONS: Final = frozenset(
    (
        "AssertionError",
        "RuntimeError",
        "ValueError",
        "TypeError",
        "ImportError",
        "ModuleNotFoundError",
        "OSError",
        "PermissionError",
        "FileNotFoundError",
        "FileExistsError",
        "NotADirectoryError",
        "IsADirectoryError",
        "TimeoutError",
        "KeyError",
        "IndexError",
        "SystemExit",
        "unknown",
    )
)
FAILURES: Final = frozenset(
    (
        "open-failed",
        "size-budget",
        "write-budget",
        "record-refused",
        "close-failed",
        "writer-lock-budget",
        "interrupted-write-budget",
        "zero-write",
        "setup-unavailable",
        "stack-arm-unavailable",
        "collection-budget",
        "collection-mismatch",
        "collection-duplicate",
        "item-index-unavailable",
        "main-sink-unavailable",
        "unknown",
    )
)
FIELDS: Final = frozenset(
    (
        "exitcode",
        "sequence",
        "monotonic",
        "utc",
        "event",
        "pid",
        "parent",
        "created",
        "identity",
        "worker",
        "role",
        "scope",
        "stage",
        "kind",
        "status",
        "name",
        "path",
        "ident",
        "known",
        "omitted",
        "expected",
        "bytes",
        "error",
        "collected",
        "total_outcomes",
        "complete",
        "failed",
        "phase",
        "outcome",
        "exception_type",
        "errno",
        "winerror",
    )
)
KINDS: Final = frozenset(
    (
        "process",
        "configuration",
        "main-sink",
        "outcome-count",
        "collection",
        "exception",
        "frame",
        "worker-down",
        "collection-report",
    )
)
STATUSES: Final = frozenset(
    (
        "live",
        "available",
        "failed",
        "unknown",
        "workspace",
        "workspace-child",
        "ancestor",
        "outside",
        "none",
        "present",
        "absent",
        "known",
    )
)
