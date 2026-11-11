"""Parent outcomes remain independent of cleanup and child session corroboration."""

import json
import shutil
import sys
from pathlib import Path

import pytest
from smoke.long_export import exported_paths, publish
from smoke.long_manifest import ControlResult, Normal, Timeout, Unknown
from smoke.long_process import run_control


def test_long_publication_failure_preserves_primary_outcome(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Requirement: actual publication refusal cannot replace the nested nonzero-exit assertion.
    project = tmp_path / "project"
    project.mkdir()
    (tmp_path / "artifacts").mkdir()
    export = tmp_path / "export"
    export.mkdir()
    (export / "long-w2").write_bytes(b"owned-publication-blocker")
    monkeypatch.setenv("SMOKE_EXPORT_ROOT", str(export))
    target = project / "test_probe.py"
    target.write_text("def test_probe():\n    raise RuntimeError('password=private-probe-error')\n")
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-p",
        "no:cacheprovider",
        "-p",
        "pr629_diag",
        "-o",
        "faulthandler_timeout=0",
        "-q",
        str(target),
        "-n",
        "2",
        "--dist",
        "loadfile",
    ]
    with pytest.raises(AssertionError, match="Nested long control exited with code 1") as primary:
        run_control(command, tmp_path)
    assert "Long control evidence is incomplete." in getattr(primary.value, "__notes__", [])


@pytest.mark.parametrize("completed_long_receipts", ["pass", "failure", "internal"], indirect=True)
def test_actual_normal_outcome_matches_numeric_witness(completed_long_receipts: Path) -> None:
    # Requirement: actual waits 0/1/3 match controller session witnesses before acceptance.
    from artifact_policy import Sanitizer
    from smoke.long_records import control_records

    destination = completed_long_receipts / "export/long-w2"
    metadata = json.loads((destination / "manifest.json").read_bytes())
    controller = next(destination.glob("*-controller.jsonl"))
    control = control_records(controller.read_bytes(), Sanitizer({}))
    assert control.session_exitcode == metadata["root_code"]
    assert control.terminal and metadata["complete"] is True
    assert len(exported_paths(destination)) == 4


@pytest.mark.parametrize(
    "state", ["timeout", "unknown", "missing", "mismatch", "duplicate", "invalid"]
)
def test_outcome_and_witness_cannot_falsely_complete(
    completed_long_receipts: Path,
    tmp_path: Path,
    state: str,
) -> None:
    # Requirement: terminal bytes cannot upgrade unknown/timeout, nor supply a missing/bad witness.
    source = tmp_path / "source"
    shutil.copytree(completed_long_receipts / "long-control-private", source)
    controller = next(source.glob("*-controller.jsonl"))
    values = [json.loads(line) for line in controller.read_bytes().splitlines()]
    witness = next(r for r in values if "exitcode" in r)
    if state == "missing":
        values.remove(witness)
    if state == "mismatch":
        witness["exitcode"] = 1
    if state == "duplicate":
        values.insert(values.index(witness) + 1, dict(witness))
    if state == "invalid":
        witness["exitcode"] = True
    for index, record in enumerate(values):
        record["sequence"] = index
    controller.write_text("".join(json.dumps(r) + "\n" for r in values))
    outcome = Timeout() if state == "timeout" else Unknown() if state == "unknown" else Normal(0)
    destination = tmp_path / "long-w2"
    assert not publish(source, destination, ControlResult(2, outcome))
    metadata = json.loads((destination / "manifest.json").read_bytes())
    assert metadata["root_code"] == (None if state in ("timeout", "unknown") else 0)
    expected = {
        "timeout": "control-timeout",
        "unknown": "root-outcome-unavailable",
        "missing": "controller-exit-missing",
        "mismatch": "controller-exit-mismatch",
        "duplicate": "long-source-refused",
        "invalid": "long-source-refused",
    }[state]
    assert expected in metadata["issues"]
    assert exported_paths(destination)
