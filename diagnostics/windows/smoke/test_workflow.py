"""Service tag and ordinary-lane compatibility, executed without Actions."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = Path(
    os.environ.get(
        "SERVICE_WORKFLOW_CURRENT", str(ROOT / ".github/workflows/windows-preflight.yml")
    )
)
BASE = "101e7e9fdb2c9dbd64d9721e14318ca66ecf4a32"


def test_diagnostic_finalization_uses_valid_status_and_audited_upload() -> None:
    # Requirement: valid cancellation status and guarded finalization preserve audited uploads.
    workflow = YAML(typ="safe").load(WORKFLOW)
    steps = workflow["jobs"]["windows"]["steps"]
    named_steps = {step["name"]: step for step in steps}
    receipt = named_steps["Record diagnostic step outcome"]
    audit = named_steps["Audit diagnostic evidence independently"]
    upload = named_steps["Upload diagnostic evidence"]

    assert receipt["env"]["DIAG_CANCELLED"] == "${{ job.status == 'cancelled' }}"
    assert receipt["env"]["DIAG_STEP_OUTCOME"] == "${{ steps.diagnostic_test.outcome }}"
    for step in (receipt, audit, upload):
        assert step["if"] == (
            "always() && matrix.check == 'Test' && steps.source.outputs.diagnostic == 'true'"
        )
    assert audit["id"] == "audit"
    assert upload["with"]["path"] == "${{ steps.audit.outputs.paths }}"
    assert upload["with"]["if-no-files-found"] == "error"
    assert steps.index(receipt) < steps.index(audit) < steps.index(upload)


@pytest.mark.parametrize(
    ("suffix", "code", "diagnostic", "workers"),
    [
        ("", 0, "false", "2"),
        ("-diag-w2", 0, "true", "2"),
        ("-diag-w1", 0, "true", "1"),
        ("-diag-w1-tail", 1, "", ""),
        ("-diag-w2-tail", 1, "", ""),
        ("-diag-w4", 1, "", ""),
        ("-diag-w0", 1, "", ""),
        ("-diag-w2;echo bad", 1, "", ""),
        ("\n", 1, "", ""),
    ],
)
def test_tag_modes(tmp_path: Path, suffix: str, code: int, diagnostic: str, workers: str) -> None:
    # Requirement: only strict 1/2 diagnostics run; reserved tail and argv injection fail.
    workflow = YAML(typ="safe").load(WORKFLOW)
    parser = workflow["jobs"]["windows"]["steps"][0]["run"]
    output = tmp_path / "output"
    source = "a" * 40
    result = subprocess.run(
        [sys.executable, "-c", parser],
        env={
            **os.environ,
            "GITHUB_REF_NAME": f"windows-preflight/{source}-123{suffix}",
            "GITHUB_OUTPUT": str(output),
            "GITHUB_ENV": str(tmp_path / "environment"),
        },
        stdout=None,
        stderr=None,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == code
    if code == 0:
        assert output.read_text() == (f"sha={source}\ndiagnostic={diagnostic}\nworkers={workers}\n")
    else:
        assert not output.exists()


def test_ordinary_jobs_preserve_service_base() -> None:
    # Requirement: the real shipped ordinary command, jobs, limits and smoke remain unchanged.
    base_text = (
        Path(os.environ["SERVICE_WORKFLOW_BASE"]).read_text(encoding="utf-8-sig")
        if "SERVICE_WORKFLOW_BASE" in os.environ
        else subprocess.check_output(
            ["git", "show", f"{BASE}:.github/workflows/windows-preflight.yml"],
            cwd=ROOT,
            env={**os.environ, "GIT_MASTER": "1"},
            text=True,
            timeout=10,
        )
    )
    base = YAML(typ="safe").load(base_text)
    current = YAML(typ="safe").load(WORKFLOW)
    old_job, new_job = base["jobs"]["windows"], current["jobs"]["windows"]
    assert {k: v for k, v in old_job.items() if k != "steps"} == {
        k: v for k, v in new_job.items() if k != "steps"
    }
    new_steps = {step["name"]: step for step in new_job["steps"]}
    for step in old_job["steps"][1:]:
        candidate = dict(new_steps[step["name"]])
        if step["name"] == "Run tests with coverage":
            assert candidate.pop("if") == (
                "matrix.check == 'Test' && steps.source.outputs.diagnostic != 'true'"
            )
            candidate["if"] = step["if"]
        assert candidate == step
    assert current["on"] == base["on"]
    assert current["permissions"] == base["permissions"]
