"""Fixed production argv shared by execution, provenance and behavioral smoke."""

from __future__ import annotations


def pytest_argv(workers: str) -> list[str]:
    if workers not in ("1", "2"):
        raise SystemExit("Diagnostic workers must be 1 or 2.")
    return [
        "uv",
        "run",
        "pytest",
        "-p",
        "no:cacheprovider",
        "-n",
        workers,
        "--dist",
        "loadfile",
        "-v",
        "--durations=200",
        "--durations-min=0.5",
        "--cov=src/conductor",
        "--cov-report=xml",
        "--cov-report=term-missing",
        "-m",
        "not real_api and not install_scripts and not performance and not docker_integration",
        "-p",
        "pr629_diag",
        "-o",
        "faulthandler_timeout=0",
    ]
