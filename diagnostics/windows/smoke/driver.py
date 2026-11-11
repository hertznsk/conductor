"""Bounded subprocess entry for service tests; never used by the production entry point."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

import psutil
import windows_identity
from process_identity import Identity
from process_samples import Ledger
from supervisor import Budget, interrupted, pytest_argv, supervise


def main() -> int:
    artifacts = Path(sys.argv[1])
    fault = os.environ.get("SMOKE_BINDING_FAULT")
    if sys.argv[2] == "production":
        command = pytest_argv(sys.argv[3])
    else:
        command = json.loads(Path(sys.argv[2]).read_text())
    signal.signal(signal.SIGTERM, interrupted)
    if sys.platform == "win32":
        signal.signal(signal.SIGBREAK, interrupted)
    budget = Budget(time.monotonic(), seconds=90, grace=0.5)
    if fault == "native":
        kernel = windows_identity.kernel_api()
        with (
            patch.object(kernel, "GetProcessTimes", side_effect=OSError("synthetic")),
            patch.object(windows_identity, "kernel_api", return_value=kernel),
        ):
            code = supervise(command, artifacts, budget)
    elif fault == "final":
        with patch.object(Ledger, "finish", side_effect=OSError("synthetic")):
            code = supervise(command, artifacts, budget)
    elif fault:
        failure = {"nosuch": psutil.NoSuchProcess(1), "denied": psutil.AccessDenied(1)}.get(
            fault, OSError("synthetic")
        )
        with patch.object(Identity, "child", side_effect=failure):
            code = supervise(command, artifacts, budget)
    else:
        with patch.object(subprocess, "Popen", wraps=subprocess.Popen) as launches:
            code = supervise(command, artifacts, budget)
        assert launches.call_count == 1, "Observer launched an external helper."
    if sys.platform == "win32":
        return code if code < 2**31 else code - 2**32
    return code if code >= 0 else 128 - code


if __name__ == "__main__":
    sys.exit(main())
