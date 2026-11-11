#!/usr/bin/env python
# /// script
# requires-python = ">=3.13"
# dependencies = ["psutil>=6"]
# ///
# Run in the source checkout: uv run python <RUNNER_TEMP>/windows-preflight-diagnostic/receipt.py
"""Setup-only provenance. No command here is called during target observation."""

from __future__ import annotations

import hashlib
import importlib.metadata
import os
import subprocess
import sys
from pathlib import Path

import psutil
from artifact_policy import LEVEL, MIB, environment_sanitizer
from diagnostic_sink import Sink
from supervisor import pytest_argv


def git_revision(revision: str) -> str:
    return subprocess.check_output(
        ["git", "rev-parse", revision],
        env={**os.environ, "GIT_MASTER": "1"},
        text=True,
        timeout=10,
    ).strip()


def main() -> int:
    root = Path(os.environ["RUNNER_TEMP"]) / "windows-preflight-diagnostic"
    artifacts = root / "artifacts"
    head = git_revision("HEAD")
    service = (artifacts / "service-checkout-head.txt").read_text(encoding="utf-8-sig").strip()
    if head != os.environ["DIAG_SOURCE_SHA"] or service != os.environ["DIAG_SERVICE_SHA"]:
        raise SystemExit("Provenance mismatch.")
    sink = Sink(artifacts / "environment.jsonl", environment_sanitizer(), MIB)
    # Hosted image metadata uses these case-sensitive protocol keys.
    image = {name: os.environ.get(name) for name in ("ImageOS", "ImageVersion")}
    sink.emit(
        {
            "event": "environment",
            "level": LEVEL,
            "scope": "published-source",
            "sha": head,
            "checkout_head": head,
            "tree": git_revision("HEAD^{tree}"),
            "service_sha": service,
            "service_head": service,
            "python": sys.version,
            "executable": sys.executable,
            "image_os": image["ImageOS"],
            "image_version": image["ImageVersion"],
            "lock_hash": hashlib.sha256(Path("uv.lock").read_bytes()).hexdigest(),
            "argv": pytest_argv(os.environ["DIAG_WORKERS"]),
            "cpu_count": os.cpu_count(),
            "process_cpu_count": os.process_cpu_count(),
            "affinity": psutil.Process().cpu_affinity(),
            "memory_total": psutil.virtual_memory().total,
            "memory_available": psutil.virtual_memory().available,
            "disk_total": psutil.disk_usage(str(Path.cwd())).total,
            "disk_free": psutil.disk_usage(str(Path.cwd())).free,
        }
    )
    for package in (
        "pytest",
        "pytest-xdist",
        "pytest-cov",
        "coverage",
        "psutil",
        "github-copilot-sdk",
        "claude-agent-sdk",
    ):
        sink.emit(
            {"event": "version", "package": package, "version": importlib.metadata.version(package)}
        )
    sink.emit(
        {
            "event": "version",
            "package": "uv",
            "version": subprocess.check_output(["uv", "--version"], text=True, timeout=10).strip(),
        }
    )
    for path in sorted(root.rglob("*")):
        if path.suffix not in (".py", ".yml"):
            continue
        sink.emit(
            {
                "event": "service-file",
                "path": str(path.relative_to(root)),
                "sha": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    sink.emit(
        {"event": "scope", "name": "cim_inventory", "status": "not_collected_by_preliminary_scope"}
    )
    sink.emit(
        {
            "event": "scope",
            "name": "windows_wait_reason",
            "status": "not_collected_by_preliminary_scope",
        }
    )
    sink.emit({"event": "scope", "name": "native_capture", "status": "disabled"})
    sink.close()
    return 0 if sink.failure is None else 1


if __name__ == "__main__":
    sys.exit(main())
