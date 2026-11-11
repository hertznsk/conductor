#!/usr/bin/env python
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///
# Run: uv run python <RUNNER_TEMP>/windows-preflight-diagnostic/artifact_audit.py
"""Independent always audit. The evidence outcome cannot overwrite the target outcome."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path

from artifact_policy import (
    BUNDLE_CAP,
    COVERAGE_CAP,
    LEVEL,
    LOG_CAP,
    MANDATORY_RECORDS,
    MIB,
    SCHEMA,
    STACK_CAP,
    UnsafeArtifact,
    environment_sanitizer,
)
from artifact_snapshot import (
    Parsed,
    bounded_snapshot,
    coverage_snapshot,
    prefix_records,
    records,
    stack_snapshot,
)
from audit_contract import assess
from comparison_summary import summarize_resources, summarize_timing


@dataclass(frozen=True, slots=True)
class Artifact:
    path: str
    kind: str
    status: str
    bytes: int = 0
    sha256: str | None = None
    reason: str | None = None
    producer: str | None = None
    source_bytes: int | None = None
    cutoff_monotonic: float | None = None


def audit(source: Path, staging: Path) -> bool:
    sanitizer = environment_sanitizer()
    # A fresh directory is a publication lease; never follow a pre-existing staging symlink.
    staging.mkdir()
    inventory: list[Artifact] = []
    summaries: dict[str, Parsed] = {}
    paths: list[str] = []
    total = 0
    complete = True
    expected = list(MANDATORY_RECORDS)
    phase_paths = sorted(source.glob("*.phase.jsonl"))
    for phase in phase_paths:
        if not re.fullmatch(r"\d+-(?:controller|gw\d+)\.phase\.jsonl", phase.name):
            complete = False
            continue
        expected.append(phase.name)
        expected.append("private/" + phase.name.replace(".phase.jsonl", ".stack.txt"))
    # Coverage is conditional only on a normal test outcome, determined below.
    for name in expected:
        kind = "stack" if name.startswith("private/") else "records"
        cap = (
            STACK_CAP
            if kind == "stack"
            else (
                MIB if name in ("environment.jsonl", "supervisor.jsonl", "step.jsonl") else LOG_CAP
            )
        )
        published_name = name.removeprefix("private/")
        source_bytes: int | None = None
        try:
            if not (source / name).is_symlink():
                source_bytes = (source / name).stat().st_size
            content = bounded_snapshot(source / name, cap)
            if kind == "stack":
                phase_name = published_name.replace(".stack.txt", ".phase.jsonl")
                phase_summary = summaries.get(phase_name, Parsed())
                first = phase_summary.first
                if not isinstance(first.get("identity"), str):
                    raise UnsafeArtifact("stack-producer-unavailable")
                if phase_summary.max_gap >= 60 and not content:
                    raise UnsafeArtifact("missing-watchdog-stack")
                cleaned = stack_snapshot(content, sanitizer)
            else:
                cleaned, summaries[name] = records(content, sanitizer)
                if summaries[name].producer_incomplete:
                    raise UnsafeArtifact("producer-incomplete")
                first = summaries[name].first
                if name.endswith(".phase.jsonl"):
                    pid, worker = name.removesuffix(".phase.jsonl").split("-", 1)
                    if (
                        first.get("event") != "start"
                        or first.get("pid") != int(pid)
                        or first.get("worker") != worker
                    ):
                        raise UnsafeArtifact("phase-producer-mismatch")
            if total + len(cleaned) > BUNDLE_CAP - MIB:
                raise UnsafeArtifact("bundle-cap")
            # The final bounded scan sees the complete serialized bytes, not read chunks.
            sanitizer.published(cleaned.decode("utf-8"), cap)
            destination = staging / published_name
            destination.write_bytes(cleaned)
            paths.append(str(destination))
            total += len(cleaned)
            identity = first.get("identity")
            inventory.append(
                Artifact(
                    published_name,
                    kind,
                    "complete",
                    len(cleaned),
                    hashlib.sha256(cleaned).hexdigest(),
                    producer=identity if isinstance(identity, str) else None,
                    source_bytes=source_bytes,
                    cutoff_monotonic=time.monotonic(),
                )
            )
        except UnsafeArtifact as error:
            complete = False
            inventory.append(
                Artifact(
                    published_name, kind, "withheld", reason=error.reason, source_bytes=source_bytes
                )
            )
        except FileNotFoundError:
            complete = False
            inventory.append(Artifact(published_name, kind, "missing", reason="not-found"))
        except (OSError, ValueError, TypeError, UnicodeError):
            complete = False
            inventory.append(
                Artifact(
                    published_name,
                    kind,
                    "error",
                    reason="unreadable-or-corrupt",
                    source_bytes=source_bytes,
                )
            )
    prefixes = {
        name: prefix_records(source / name, sanitizer)
        for name in expected
        if not name.startswith("private/") and name != "step.jsonl"
    }
    outcome_summaries: dict[str, Parsed] = {}
    for name in ("supervisor.jsonl", "post-root.jsonl"):
        if name not in summaries and prefixes[name].content:
            try:
                _, outcome_summaries[name] = records(prefixes[name].content, sanitizer)
            except UnsafeArtifact:
                # Only validated whole records may corroborate a root outcome.
                continue
    assessment = assess(summaries, [phase.name for phase in phase_paths], outcome_summaries)
    comparisons = {}
    for label, reducer, selected in (
        (
            "resources",
            summarize_resources,
            {
                k: v
                for k, v in prefixes.items()
                if k in ("supervisor.jsonl", "processes.jsonl", "post-root.jsonl")
            },
        ),
        (
            "timing",
            summarize_timing,
            {
                k: v
                for k, v in prefixes.items()
                if k == "supervisor.jsonl" or k.endswith(".phase.jsonl")
            },
        ),
    ):
        summary = reducer(selected, sanitizer)
        payload = json.dumps(asdict(summary), sort_keys=True).encode()
        filename = ("resource" if label == "resources" else "timing") + "-summary.json"
        try:
            if len(payload) > MIB:
                raise UnsafeArtifact("comparison-summary-cap")
            if total + len(payload) > BUNDLE_CAP - MIB:
                raise UnsafeArtifact("bundle-cap")
            sanitizer.published(payload.decode(), MIB)
            destination = staging / filename
            destination.write_bytes(payload)
            paths.append(str(destination))
            total += len(payload)
            inventory.append(
                Artifact(
                    filename,
                    "comparison",
                    "complete",
                    len(payload),
                    hashlib.sha256(payload).hexdigest(),
                )
            )
            comparisons[label] = {
                "status": summary.measurement_status,
                "reasons": summary.reasons,
                "bounds": summary.bounds,
                "path": filename,
            }
        except UnsafeArtifact as error:
            complete = False
            inventory.append(
                Artifact(
                    filename,
                    "comparison",
                    "withheld",
                    reason=error.reason,
                    source_bytes=len(payload),
                )
            )
            comparisons[label] = {
                "status": "unavailable",
                "reasons": [error.reason],
                "bounds": summary.bounds,
                "path": filename,
            }
    complete = complete and assessment.structured_complete and not any(source.glob("*.failure"))
    lifecycle = assessment.lifecycle_complete
    root, provenance, timeline = assessment.root, assessment.provenance, assessment.timeline
    required_roles = assessment.expected_roles
    environment = summaries.get("environment.jsonl", Parsed())
    coverage_path = source / "coverage.xml"
    if root.get("root_code") in (0, 1):
        try:
            cleaned = coverage_snapshot(bounded_snapshot(coverage_path, COVERAGE_CAP), sanitizer)
            sanitizer.published(cleaned.decode("utf-8"), COVERAGE_CAP)
            if total + len(cleaned) > BUNDLE_CAP - MIB:
                raise UnsafeArtifact("bundle-cap")
            destination = staging / "coverage.xml"
            destination.write_bytes(cleaned)
            paths.append(str(destination))
            total += len(cleaned)
            inventory.append(
                Artifact(
                    "coverage.xml",
                    "coverage",
                    "complete",
                    len(cleaned),
                    hashlib.sha256(cleaned).hexdigest(),
                )
            )
        except (OSError, ValueError, ET.ParseError, UnicodeError, UnsafeArtifact):
            complete = False
            inventory.append(
                Artifact("coverage.xml", "coverage", "withheld", reason="missing-corrupt-unsafe")
            )
    else:
        inventory.append(
            Artifact("coverage.xml", "coverage", "not-applicable", reason="test-incomplete")
        )
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    manifest = {
        "schema": SCHEMA,
        "level": LEVEL,
        "native_capture": "disabled",
        "full_C6": "unmet",
        "full_C7": "unmet",
        "cim_inventory": "not_collected_by_preliminary_scope",
        "windows_wait_reason": "not_collected_by_preliminary_scope",
        "structured_artifacts_complete": complete,
        "observed_lifecycle_complete": lifecycle,
        "raw_log_completeness": "not_verified_by_service",
        "raw_channel": {
            "kind": "github_actions_run_log",
            "capture_mode": "inherited_runner_stdout_stderr",
            "uploaded_as_diagnostic_artifact": False,
            "service_redaction": "not_performed",
            "service_retention_cap": "not_applicable",
            "log_completeness": "not_verified_by_service",
            "run_url": f"https://github.com/hertznsk/conductor/actions/runs/{run_id}"
            if re.fullmatch(r"[0-9]{1,30}", run_id)
            else None,
            "run_id": run_id if re.fullmatch(r"[0-9]{1,30}", run_id) else None,
            "run_attempt": run_attempt if re.fullmatch(r"[0-9]{1,10}", run_attempt) else None,
            "job_key": "windows",
            "matrix_check": "Test",
            "test_step_name": "Verify the diagnostic service on hosted Windows"
            if provenance.get("scope") == "synthetic-project"
            else "Run diagnostic tests with coverage",
        },
        "provenance": provenance,
        "root_outcome": root,
        "versions": [record for record in environment.kept if record["event"] == "version"],
        "service_files": [
            record for record in environment.kept if record["event"] == "service-file"
        ],
        "step_outcome": summaries.get("step.jsonl", Parsed()).last,
        "expected_roles": sorted(required_roles),
        "missing_roles": sorted(assessment.missing_roles),
        "physical_timeline": timeline,
        **assessment.cleanup,
        "close_errors": assessment.close_errors,
        "diagnostic_warnings": ["exited-process-close-failed"] if assessment.close_warning else [],
        "comparison_evidence": comparisons,
        "artifacts": [asdict(item) for item in inventory],
        "published_bytes": total,
        "budgets": {
            "record": 65536,
            "field": 4096,
            "phase": LOG_CAP,
            "process": LOG_CAP,
            "stack": STACK_CAP,
            "coverage": COVERAGE_CAP,
            "bundle": BUNDLE_CAP,
        },
        "residual_risk": "Unknown or transformed secrets may evade exact/pattern checks. "
        "Actions output is not sanitized by this service. Private spool is uncapped.",
    }
    payload = json.dumps(manifest, indent=2).encode()
    manifest_path = str(staging / "manifest.json")
    output_receipt = (
        "paths<<DIAGNOSTIC_PATHS\n" + "\n".join([*paths, manifest_path]) + "\nDIAGNOSTIC_PATHS\n"
    )
    if len(payload) > MIB or total + len(payload) + len(output_receipt.encode()) > BUNDLE_CAP:
        # Nothing outside the explicit path receipt is uploaded. Leave owned staging bytes private.
        reason = "manifest-cap" if len(payload) > MIB else "bundle-cap"
        complete = False
        counts = {
            status: sum(item.status == status for item in inventory)
            for status in ("complete", "withheld", "missing", "error", "not-applicable")
        }
        manifest = {
            "schema": SCHEMA,
            "level": LEVEL,
            "native_capture": "disabled",
            "full_C6": "unmet",
            "full_C7": "unmet",
            "structured_artifacts_complete": False,
            "observed_lifecycle_complete": lifecycle,
            "root_outcome": root,
            "provenance": {
                key: provenance.get(key)
                for key in ("scope", "sha", "tree", "checkout_head", "service_sha", "service_head")
            },
            "publication_failure": reason,
            "published_bytes": 0,
            "source_artifact_counts": counts,
            "artifact_details_omitted": len(inventory),
            "artifacts": [
                asdict(Artifact(item["path"], "comparison", "withheld", reason=reason))
                for item in comparisons.values()
            ],
            "comparison_evidence": {
                key: {
                    "status": "unavailable",
                    "reasons": [reason],
                    "bounds": value["bounds"],
                    "path": value["path"],
                }
                for key, value in comparisons.items()
            },
            "budgets": {"manifest": MIB, "bundle": BUNDLE_CAP},
        }
        paths = []
        payload = json.dumps(manifest, indent=2).encode()
        output_receipt = "paths<<DIAGNOSTIC_PATHS\n" + manifest_path + "\nDIAGNOSTIC_PATHS\n"
    sanitizer.published(payload.decode(), MIB)
    temporary = staging / "manifest.pending"
    temporary.write_bytes(payload)
    temporary.replace(staging / "manifest.json")
    if output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("ab") as stream:
            stream.write(output_receipt.encode("utf-8"))
    return complete and lifecycle


if __name__ == "__main__":
    root = Path(os.environ["RUNNER_TEMP"]) / "windows-preflight-diagnostic"
    sys.exit(0 if audit(root / "artifacts", root / "published") else 1)
