"""Closed manifest boundary exercised using genuine normal-failure receipts."""

import json
import shutil
from pathlib import Path

import pytest
from artifact_policy import UnsafeArtifact
from smoke.long_export import exported_paths, publish
from smoke.long_manifest import ControlResult, Unknown


@pytest.mark.parametrize("completed_long_receipts", ["failure"], indirect=True)
@pytest.mark.parametrize(
    "damage",
    [
        "h1-unknown",
        "root-one-to-zero",
        "entry-nodeid",
        "entry-message",
        "timeout-with-code",
        "root-code-bool",
        "root-code-string",
        "timeout-int",
        "complete-int",
        "cleanup-int",
        "entry-bytes-float",
        "entry-terminal-int",
        "entry-reason-vocab",
        "error-vocab",
        "issues-vocab-complete",
        "issues-vocab-incomplete",
        "issues-type-incomplete",
        "root-code-float",
        "withheld-extra",
        "withheld-terminal",
        "top-extra",
        "duplicate-key",
        "root-array",
        "partial-missing-issue",
        "roles-duplicate",
    ],
)
def test_manifest_refuses_hostile_metadata(
    completed_long_receipts: Path,
    tmp_path: Path,
    damage: str,
) -> None:
    # Requirement: real failure1 is accepted first; hostile metadata never widens the whitelist.
    original = completed_long_receipts / "export/long-w2"
    assert len(exported_paths(original)) == 4
    metadata = json.loads((original / "manifest.json").read_bytes())
    assert metadata["root_code"] == 1 and metadata["complete"] is True
    destination = tmp_path / "long-w2"
    if damage == "h1-unknown":
        assert not publish(
            completed_long_receipts / "long-control-private",
            destination,
            ControlResult(2, Unknown()),
        )
        value = json.loads((destination / "manifest.json").read_bytes())
        assert value["root_code"] is None and value["timeout"] is False
        assert value["issues"] == ["root-outcome-unavailable"]
        assert len(exported_paths(destination)) == 4
        return
    shutil.copytree(original, destination)
    entry = metadata["receipts"][0]
    match damage:
        case "root-one-to-zero":
            metadata["root_code"] = 0
        case "entry-nodeid" | "entry-message":
            entry[damage.removeprefix("entry-")] = "QA_PUBLIC_PARAMETER"
        case "timeout-with-code":
            metadata["timeout"] = True
        case "root-code-bool":
            metadata["root_code"] = False
        case "root-code-string":
            metadata["root_code"] = "0"
        case "root-code-float":
            metadata["root_code"] = 1.0
        case "timeout-int":
            metadata["timeout"] = 0
        case "complete-int":
            metadata["complete"] = 1
        case "cleanup-int":
            metadata["cleanup_complete"] = 1
        case "entry-bytes-float":
            entry["bytes"] = float(entry["bytes"])
        case "entry-terminal-int":
            entry["terminal"] = 1
        case "entry-reason-vocab":
            entry["reason"] = "QA_PUBLIC_BAD_REASON"
        case "error-vocab":
            metadata["error"] = "QA_PUBLIC_BAD_ERROR"
        case "issues-vocab-complete" | "issues-vocab-incomplete" | "issues-type-incomplete":
            metadata["issues"] = [314 if damage == "issues-type-incomplete" else "QA_BAD"]
            metadata["complete"] = damage == "issues-vocab-complete"
        case "withheld-extra" | "withheld-terminal":
            entry.update(status="withheld", bytes=0, sha256=None, reason="long-source-refused")
            metadata.update(complete=False, issues=["long-source-refused", "role-missing"])
            if damage == "withheld-extra":
                entry["argv"] = ["QA_PUBLIC_PARAMETER"]
            else:
                entry["terminal"] = 1
        case "top-extra":
            metadata["locals"] = "QA_PUBLIC_PARAMETER"
        case "roles-duplicate":
            metadata["expected_roles"].append("gw0")
        case "partial-missing-issue":
            metadata.update(root_code=None, complete=False)
        case "duplicate-key" | "root-array":
            pass
    payload = json.dumps(metadata)
    if damage == "duplicate-key":
        payload = payload[:-1] + ', "root_code": 1}'
    if damage == "root-array":
        payload = "[]"
    (destination / "manifest.json").write_text(payload)
    with pytest.raises(UnsafeArtifact):
        exported_paths(destination)
