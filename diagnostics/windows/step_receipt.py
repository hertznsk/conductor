#!/usr/bin/env python
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///
# Run: uv run python <RUNNER_TEMP>/windows-preflight-diagnostic/step_receipt.py
"""Always step receipt; copy coverage only after a bounded read, never an unlimited file copy."""

import os
import sys
from pathlib import Path

from artifact_policy import COVERAGE_CAP, MIB, UnsafeArtifact, environment_sanitizer
from artifact_snapshot import bounded_snapshot
from diagnostic_sink import Sink


def main() -> int:
    artifacts = Path(os.environ["RUNNER_TEMP"]) / "windows-preflight-diagnostic" / "artifacts"
    sink = Sink(artifacts / "step.jsonl", environment_sanitizer(), MIB)
    sink.emit(
        {
            "event": "step",
            "outcome": os.environ["DIAG_STEP_OUTCOME"],
            "interrupted": os.environ.get("DIAG_CANCELLED") == "true",
        }
    )
    if Path("coverage.xml").exists():
        try:
            (artifacts / "coverage.xml").write_bytes(
                bounded_snapshot(Path("coverage.xml"), COVERAGE_CAP)
            )
        except (OSError, UnsafeArtifact):
            sink.fail("coverage-unavailable")
    sink.close()
    return 0 if sink.failure is None else 1


if __name__ == "__main__":
    sys.exit(main())
