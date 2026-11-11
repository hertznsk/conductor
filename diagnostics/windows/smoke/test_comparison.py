"""Fixed-clock comparison reducers and independent close qualification controls."""

from __future__ import annotations

import hashlib
import io
import json
from collections.abc import Mapping
from dataclasses import asdict
from pathlib import Path
from typing import IO

import artifact_audit
import pytest
from artifact_audit import audit
from artifact_policy import (
    MANDATORY_RECORDS,
    MIB,
    SCHEMA,
    Record,
    Sanitizer,
    UnsafeArtifact,
)
from artifact_snapshot import Parsed, Prefix, prefix_records, records
from audit_contract import assess
from comparison_summary import Summary, summarize_resources, summarize_timing


def encoded(events: list[Record]) -> bytes:
    return b"".join(
        (json.dumps({"sequence": i, "monotonic": float(i), **r}) + "\n").encode()
        for i, r in enumerate(events)
    )


def prefix(tmp_path: Path, events: list[Record]) -> Prefix:
    path = tmp_path / "input.jsonl"
    path.write_bytes(encoded(events))
    return prefix_records(path, Sanitizer({}))


def assessment_streams() -> dict[str, list[Record]]:
    cleanup: Record = {
        "close_errors_count": 1,
        "close_errors_recorded": 1,
        "close_error_evidence_complete": True,
        "observer_cleanup_status": "close-error",
    }
    exit_fields: Record = {
        **cleanup,
        "root_code": 1,
        "complete": True,
        "interrupted": False,
        "observer_failed": False,
        "observation_detached": False,
    }
    physical = [
        {
            "event": "observed",
            "pid": i + 1,
            "identity": f"{i + 1}:creation",
            "role": role,
            "status": "proved-exited",
            "first_exit": 0.0,
        }
        for i, role in enumerate(("controller", "gw0"))
    ]
    close: Record = {
        **physical[1],
        "event": "process.close_error",
        "stage": "observe-exited",
        "reason": "process-handle-close-failed",
        "exception_type": "PermissionError",
        "errno": 13,
        "winerror": None,
    }
    streams: dict[str, list[Record]] = {
        "supervisor.jsonl": [
            {
                "event": "expected",
                "policy": SCHEMA,
                "workers": 1,
                "expected_files": list(MANDATORY_RECORDS),
                "argv": ["pytest"],
            },
            {**physical[0], "event": "binding"},
            close,
            {"event": "root-exit", "exitcode": 1},
            {"event": "exit", **exit_fields},
        ],
        "processes.jsonl": [{"event": "host"}, {"event": "process"}, *physical],
        "post-root.jsonl": [
            {"event": "post.begin", "known": 2},
            *physical,
            {"event": "post.end", **exit_fields},
        ],
        "environment.jsonl": [
            {"event": "environment", "scope": "synthetic-project", "argv": ["pytest"]}
        ],
    }
    for role in ("controller", "gw0"):
        streams[f"{role}.phase.jsonl"] = [
            {"event": "start", "worker": role},
            {"event": "stack-arm"},
            {"event": "collected", "item_index": 0, "label": "test.py::test_a"},
            {
                "event": "report",
                "item_index": 0,
                "phase": "call",
                "duration": 1.0,
                "label": "test.py::test_a",
                "outcome": "passed",
            },
            {
                "event": "report",
                "item_index": 0,
                "phase": "teardown",
                "duration": 0.0,
                "label": "test.py::test_a",
                "outcome": "passed",
            },
            {"event": "sessionfinish.end"},
            {"event": "unconfigure.end"},
        ]
    return streams


def assessment_inputs() -> dict[str, Parsed]:
    return {
        name: records(encoded(events), Sanitizer({}))[1]
        for name, events in assessment_streams().items()
    }


@pytest.fixture
def publication_source(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    source.mkdir()
    (source / "private").mkdir()
    for name, events in assessment_streams().items():
        if name.endswith(".phase.jsonl"):
            role = str(events[0]["worker"])
            pid = 1 if role == "controller" else 2
            name = f"{pid}-{role}.phase.jsonl"
            events = [
                {"pid": pid, "identity": f"{pid}:creation", "worker": role, **r} for r in events
            ]
            (source / "private" / name.replace(".phase.jsonl", ".stack.txt")).write_bytes(b"")
        (source / name).write_bytes(encoded(events))
    (source / "step.jsonl").write_bytes(encoded([{"event": "step", "outcome": "failure"}]))
    (source / "coverage.xml").write_text("<coverage><sources/></coverage>")
    assert audit(source, tmp_path / "positive-publication")
    return source


@pytest.mark.parametrize(
    "fault",
    ["", "count", "identity", "status", "footer", "gap", "root", "schema", "first_exit", "stage"],
)
def test_warning_requires_independent_evidence(fault: str) -> None:
    # Requirement: close warnings require independent identity, exit, count and footer agreement.
    inputs = assessment_inputs()
    supervisor, post = inputs["supervisor.jsonl"], inputs["post-root.jsonl"]
    match fault:
        case "count":
            supervisor.last["close_errors_count"] = 2
        case "identity":
            supervisor.close_errors[0]["identity"] = "foreign:creation"
        case "status":
            supervisor.close_errors[0]["status"] = "live"
        case "footer":
            post.last["close_error_evidence_complete"] = False
        case "gap":
            supervisor.producer_incomplete = True
        case "root":
            supervisor.last["root_code"] = None
        case "schema":
            supervisor.kept[0]["policy"] = "windows-preflight-r3"
        case "first_exit":
            supervisor.close_errors[0]["first_exit"] = None
        case "stage":
            supervisor.close_errors[0]["stage"] = "discover-duplicate"
    result = assess(inputs, ["controller.phase.jsonl", "gw0.phase.jsonl"])
    assert result.structured_complete is (fault == "")
    assert result.close_warning is (fault == "")
    if not fault:
        assert result.lifecycle_complete and result.root["root_code"] == 1


@pytest.mark.parametrize("fault", ["", "reset", "reuse", "missing", "gap", "late"])
def test_resource_deltas_preserve_identity_and_missingness(tmp_path: Path, fault: str) -> None:
    # Requirement: counters never join reused PIDs; missing counters remain unknown.
    events: list[Record] = []
    for i, stamp in enumerate((0.0, 10.0)):
        events.append(
            {
                "event": "host",
                "monotonic": stamp,
                "sample_id": i,
                "cpu_total": 100.0 + i * 40,
                "cpu_idle": 40.0 + i * 10,
                "read_bytes": 100 + i * 50,
                "write_bytes": 200 + i * 100,
                "memory_available": 1000 - i * 100,
            }
        )
        for n, role in enumerate(("controller", "gw0")):
            events.append(
                {
                    "event": "process",
                    "monotonic": stamp,
                    "sample_id": i,
                    "identity": f"{n}:birth",
                    "role": role,
                    "cpu_user": 10.0 + i * 2,
                    "cpu_system": 2.0 + i,
                    "read_bytes": 100 + i * 30,
                    "write_bytes": 200 + i * 40,
                    "rss": 500 + i * 10,
                    "vms": 900,
                    "affinity": [0, 1],
                }
            )
    last = events[-1]
    match fault:
        case "reset":
            last["cpu_user"] = 0
        case "reuse":
            last["identity"] = "1:replacement-birth"
        case "missing":
            last.pop("read_bytes")
        case "gap":
            for r in events[3:]:
                r["monotonic"], r["sample_id"] = 40.0, 4
        case "late":
            pass
    samples = prefix(tmp_path, events)
    ending = prefix(
        tmp_path,
        [
            {
                "event": "observed",
                "identity": f"{i}:birth",
                "role": role,
                "first_exit": 40.0 if fault == "late" else 11.0,
            }
            for i, role in enumerate(("controller", "gw0"))
        ]
        + [{"event": "post.end"}],
    )
    result = summarize_resources(
        {"processes.jsonl": samples, "post-root.jsonl": ending}, Sanitizer({})
    )
    data = asdict(result)["measurements"]
    assert data["host"]["cpu_cores"] == (0.75 if fault == "gap" else 3.0)
    assert data["host"]["cpu_percent"] == 75
    assert data["groups"]["controller"]["read_bytes_delta"] == 30
    if not fault:
        assert data["groups"]["gw0"]["cpu_cores"] == 0.3
        assert data["groups"]["gw0"]["percent_measured_affinity"] == 15
        assert data["groups"]["gw0"]["sampled_rss_max"] == 510
    else:
        assert result.measurement_status == "insufficient-samples"
    assert len(data["activity"]) <= 128


def test_timing_uses_worker_intervals_and_censors_open_phase(tmp_path: Path) -> None:
    # Requirement: worker timing survives corrupt tails and reports an open teardown to its cutoff.
    phase = prefix(
        tmp_path,
        [
            {"event": "start", "worker": "gw0"},
            {"event": "collected", "worker": "gw0", "item_index": 0, "label": "test_a.py::test_a"},
            {
                "event": "setup.begin",
                "worker": "gw0",
                "item_index": 0,
                "label": "test_a.py::test_a",
            },
            {"event": "setup.end", "worker": "gw0", "item_index": 0, "label": "test_a.py::test_a"},
            {
                "event": "report",
                "worker": "gw0",
                "item_index": 0,
                "phase": "setup",
                "outcome": "passed",
                "label": "test_a.py::test_a",
                "duration": 0.25,
            },
            {
                "event": "teardown.begin",
                "worker": "gw0",
                "item_index": 0,
                "label": "test_a.py::test_a",
            },
        ],
    )
    result = summarize_timing({"1-gw0.phase.jsonl": phase}, Sanitizer({}))
    worker = asdict(result)["measurements"]["workers"]["gw0"]
    assert worker["phase_wall_seconds"]["setup"] == 1.0
    assert worker["reported_duration_sum"]["setup"] == 0.25
    assert worker["open_phases"] == [
        {"item_index": 0, "phase": "teardown", "begin": 5.0, "observed_until": 5.0}
    ]
    assert result.right_censored and result.measurement_status == "limited"
    assert result.sha256 == hashlib.sha256(phase.content).hexdigest()


def test_timing_reduces_current_size_collection_without_cutoff(tmp_path: Path) -> None:
    # Requirement: more than 6000 reports span the full executed range with bounded top50/buckets.
    events: list[Record] = [{"event": "start", "worker": "gw0"}]
    for i in range(9000):
        events.extend(
            [
                {
                    "event": "collected",
                    "worker": "gw0",
                    "item_index": i,
                    "label": f"test_{i % 80}.py::test_a",
                },
                {
                    "event": "report",
                    "worker": "gw0",
                    "item_index": i,
                    "label": f"test_{i % 80}.py::test_a",
                    "phase": "call",
                    "outcome": "passed",
                    "duration": 0.1,
                },
            ]
        )
    events.append({"event": "unconfigure.end", "worker": "gw0"})
    source = prefix(tmp_path, events)
    result = summarize_timing({"1-gw0.phase.jsonl": source}, Sanitizer({}))
    data = asdict(result)["measurements"]
    assert data["workers"]["gw0"]["last_active_item_index"] == 8999
    assert data["workers"]["gw0"]["completed_outcomes"]["call:passed"] == 9000
    assert len(data["files_top50"]) == 50 and len(data["activity"]) <= 128
    assert source.records_consumed == 18002 and not result.right_censored
    assert len(json.dumps(asdict(result)).encode()) <= 1024 * 1024


@pytest.mark.parametrize("boundary", ["strict", "prefix", "publication"])
@pytest.mark.parametrize(
    "fault",
    [
        "collection-parameter",
        "report-parameter",
        "mapping",
        "unknown-index",
        "nonphase-parameter",
        "nonphase-mapping",
    ],
)
def test_forged_identity_is_refused_at_every_boundary(
    publication_source: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    fault: str,
) -> None:
    # Requirement: independent parsing never republishes parameters or a changed collected identity.
    bad = "test.py::test_a[private-parameter]"
    for path in publication_source.glob("*.phase.jsonl"):
        events = [json.loads(line) for line in path.read_bytes().splitlines()]
        for event in events:
            if event["event"] == "stack-arm" and fault == "nonphase-parameter":
                event.update(item_index=0, label=bad)
            if event["event"] == "sessionfinish.end" and fault == "nonphase-mapping":
                event.update(item_index=0, label="other.py::test_other")
            if event["event"] == "collected" and fault == "collection-parameter":
                event["label"] = bad
            if event["event"] == "report":
                if fault in ("collection-parameter", "report-parameter"):
                    event["label"] = bad
                elif fault == "mapping":
                    event["label"] = "other.py::test_other"
                elif fault == "unknown-index":
                    event["item_index"] = 1
        path.write_bytes(encoded(events))
    path = publication_source / "1-controller.phase.jsonl"
    match boundary:
        case "strict":
            with pytest.raises(UnsafeArtifact):
                records(path.read_bytes(), Sanitizer({}))
        case "prefix":
            result = prefix_records(path, Sanitizer({}))
            expected = {
                "collection-parameter": 2,
                "nonphase-parameter": 1,
                "nonphase-mapping": 5,
            }.get(fault, 3)
            assert result.records_consumed == expected
            assert result.right_censored and result.error_counts
            assert b"private-parameter" not in result.content
        case "publication":
            staging = publication_source.parent / "negative-publication"
            output = publication_source.parent / "negative-output"
            monkeypatch.setenv("GITHUB_OUTPUT", str(output))
            assert not audit(publication_source, staging)
            manifest = json.loads((staging / "manifest.json").read_text())
            assert manifest["root_outcome"]["root_code"] == 1
            assert manifest["structured_artifacts_complete"] is False
            for entry in manifest["artifacts"]:
                if entry["path"].endswith(".phase.jsonl"):
                    assert entry["status"] == "withheld"
                    assert str(staging / entry["path"]) not in output.read_text()
            for summary in staging.glob("*-summary.json"):
                assert "private-parameter" not in summary.read_text()
            timing = json.loads((staging / "timing-summary.json").read_text())
            assert timing["right_censored"] and timing["error_counts"]


@pytest.mark.parametrize("failure", ["summary", "aggregate", "manifest"])
def test_publication_caps_keep_failure_manifest_and_paths(
    publication_source: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    # Requirement: summary and aggregate limits finalize truthful bounded upload receipts.
    if failure in ("aggregate", "manifest"):
        path = publication_source / "environment.jsonl"
        environment = [json.loads(line) for line in path.read_bytes().splitlines()]
        count, width = (200, 4000) if failure == "aggregate" else (8000, 10)
        environment.extend(
            {"event": "version", "package": "p", "version": "x" * width} for _ in range(count)
        )
        path.write_bytes(encoded(environment))
    if failure != "manifest":

        def resources(inputs: Mapping[str, Prefix], sanitizer: Sanitizer) -> Summary:
            result = summarize_resources(inputs, sanitizer)
            result.measurements["controlled"] = "x" * (
                MIB if failure == "summary" else int(MIB * 0.85)
            )
            return result

        monkeypatch.setattr(artifact_audit, "summarize_resources", resources)
    if failure == "aggregate":

        def timing(inputs: Mapping[str, Prefix], sanitizer: Sanitizer) -> Summary:
            result = summarize_timing(inputs, sanitizer)
            result.measurements["controlled"] = "x" * int(MIB * 0.85)
            return result

        monkeypatch.setattr(artifact_audit, "summarize_timing", timing)
        monkeypatch.setattr(artifact_audit, "BUNDLE_CAP", 3 * MIB)
    staging = publication_source.parent / "capped-publication"
    output = publication_source.parent / "capped-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    assert not audit(publication_source, staging)
    manifest_path = staging / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    assert manifest["root_outcome"]["root_code"] == 1
    assert manifest["structured_artifacts_complete"] is False
    assert manifest_path.stat().st_size <= MIB
    paths = [
        Path(line) for line in output.read_text().splitlines() if line.startswith(str(staging))
    ]
    assert manifest_path in paths
    assert sum(p.stat().st_size for p in paths) + output.stat().st_size <= artifact_audit.BUNDLE_CAP
    for entry in manifest["artifacts"]:
        if entry["status"] == "complete":
            assert staging / entry["path"] in paths
        else:
            assert staging / entry["path"] not in paths
    for p in paths:
        if p.name.endswith("-summary.json"):
            assert p.stat().st_size <= MIB


@pytest.mark.parametrize("platform_newline", ["native", "windows"])
def test_output_receipt_uses_counted_utf8_bytes_at_exact_cap(
    publication_source: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform_newline: str,
) -> None:
    # Requirement: actual multiline receipt bytes equal the LF bytes counted at the aggregate cap.
    root = publication_source.parent
    output_path = root / "calibration-output"
    original_open = Path.open

    def platform_open(
        path: Path,
        mode: str = "r",
        buffering: int = -1,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> IO[bytes] | IO[str]:
        # Preserve Path.open's boundary signature and forward the production newline selection.
        if path == output_path and "b" not in mode:
            return io.TextIOWrapper(
                io.FileIO(path, "ab"),
                encoding=encoding,
                errors=errors,
                newline="\r\n" if newline is None else newline,
            )
        return original_open(path, mode, buffering, encoding, errors, newline)

    if platform_newline == "windows":
        monkeypatch.setattr(Path, "open", platform_open)
    monkeypatch.setattr(artifact_audit, "BUNDLE_CAP", 4096)
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    calibration = root / "probe"
    assert not audit(publication_source, calibration)
    calibration_manifest = calibration / "manifest.json"
    canonical = (
        "paths<<DIAGNOSTIC_PATHS\n" + str(calibration_manifest) + "\nDIAGNOSTIC_PATHS\n"
    ).encode("utf-8")
    cap = calibration_manifest.stat().st_size + len(canonical)
    assert len(str(cap)) == len(str(artifact_audit.BUNDLE_CAP))
    assert cap < artifact_audit.BUNDLE_CAP

    staging = root / "exact"
    assert len(str(staging).encode("utf-8")) == len(str(calibration).encode("utf-8"))
    output_path = root / "exact-output"
    monkeypatch.setattr(artifact_audit, "BUNDLE_CAP", cap)
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    assert not audit(publication_source, staging)
    manifest_path = staging / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    actual = output_path.read_bytes()
    expected = ("paths<<DIAGNOSTIC_PATHS\n" + str(manifest_path) + "\nDIAGNOSTIC_PATHS\n").encode(
        "utf-8"
    )
    paths = [
        Path(line) for line in actual.decode("utf-8").splitlines() if line.startswith(str(staging))
    ]
    total = sum(p.stat().st_size for p in paths) + len(actual)
    (root / "receipt-byte-evidence.json").write_text(
        json.dumps(
            {
                "platform": platform_newline,
                "cap": cap,
                "actual_total": total,
                "manifest_bytes": manifest_path.stat().st_size,
                "receipt_bytes": len(actual),
                "counted_receipt_bytes": len(expected),
                "cr_bytes": actual.count(b"\r"),
                "lf_bytes": actual.count(b"\n"),
                "root_code": manifest["root_outcome"]["root_code"],
                "paths": [str(p) for p in paths],
            },
            indent=2,
        )
    )
    assert manifest["root_outcome"]["root_code"] == 1
    assert manifest["structured_artifacts_complete"] is False
    assert paths == [manifest_path]
    assert total == cap
    assert actual == expected and b"\r" not in actual


@pytest.mark.parametrize(
    "fault", ["", "disagreement", "missing-root-exit", "missing-post", "missing-binding"]
)
def test_recovered_root_requires_corroborated_receipts(fault: str) -> None:
    # Requirement: missing footers recover only a consistent, bound root outcome with provenance.
    inputs = assessment_inputs()
    supervisor = inputs["supervisor.jsonl"]
    supervisor.kept = [r for r in supervisor.kept if r["event"] != "exit"]
    supervisor.last = next(r for r in supervisor.kept if r["event"] == "root-exit")
    supervisor.events.remove("exit")
    match fault:
        case "disagreement":
            inputs["post-root.jsonl"].last["root_code"] = 0
        case "missing-root-exit":
            supervisor.kept = [r for r in supervisor.kept if r["event"] != "root-exit"]
        case "missing-post":
            inputs.pop("post-root.jsonl")
        case "missing-binding":
            supervisor.kept = [r for r in supervisor.kept if r["event"] != "binding"]
    result = assess(inputs, ["controller.phase.jsonl", "gw0.phase.jsonl"])
    assert result.root["root_code"] == (1 if not fault else None)
    assert result.root["outcome_status"] == (
        "recovered" if not fault else "conflict" if fault == "disagreement" else "unknown"
    )
    assert result.root["outcome_sources"]
    assert not result.structured_complete
