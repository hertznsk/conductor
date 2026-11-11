"""Hostile receipt snapshots start from real completed nested pytest output."""

import json
import os
from pathlib import Path

import pytest
from artifact_policy import UnsafeArtifact
from smoke.long_export import exported_paths, publish
from smoke.long_manifest import ControlResult, Normal
from smoke.long_protocol import PROCESS_CAP


@pytest.mark.parametrize(
    "damage",
    [
        "missing",
        "partial",
        "racing",
        "oversize",
        "extra",
        "restarted",
        "field",
        "sequence",
        "published-digest",
        "filename",
        "exception-overflow",
    ],
)
def test_long_probe_refuses_untrusted_or_incomplete_receipts(
    completed_long_receipts: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    damage: str,
) -> None:
    # Requirement: missing/invalid/racing/excess receipts cannot become a complete or broad upload.

    source = tmp_path / "source"
    source.mkdir()
    originals = sorted((completed_long_receipts / "long-control-private").glob("*.jsonl"))
    assert len(originals) == 3
    for index, path in enumerate(originals):
        if damage == "missing" and index == 0:
            continue
        (source / path.name).write_bytes(path.read_bytes())
    target = next(source.glob("*.jsonl"))
    calls = 0
    match damage:
        case "partial":
            target.write_bytes(target.read_bytes()[:-1])
        case "oversize":
            target.write_bytes(b"x" * (PROCESS_CAP + 1))
        case "field" | "sequence":
            values = [json.loads(line) for line in target.read_bytes().splitlines()]
            if damage == "field":
                values[0]["argv"] = ["password=private-probe-not-publishable"]
            else:
                values[0]["sequence"] = 5
            target.write_text("".join(json.dumps(r) + "\n" for r in values))
        case "extra" | "restarted":
            role = "unknown" if damage == "extra" else "gw0"
            base = next(p for p in originals if p.name.endswith("-gw0.jsonl"))
            values = [json.loads(line) for line in base.read_bytes().splitlines()]
            for r in values:
                r.update(pid=99_999_999, identity="99999999:0x1.0p+0", role=role, worker=role)
            (source / f"99999999-{role}.jsonl").write_text(
                "".join(json.dumps(r) + "\n" for r in values)
            )
        case "filename":
            (source / "private-probe-parameter.jsonl").write_bytes(target.read_bytes())
        case "exception-overflow":
            values = [json.loads(line) for line in target.read_bytes().splitlines()]
            for index in range(9):
                values.append(
                    {
                        **values[0],
                        "event": "observed",
                        "stage": "error",
                        "kind": "exception",
                        "phase": "call",
                        "exception_type": "RuntimeError",
                        "known": index + 1,
                        "sequence": len(values),
                        "monotonic": values[-1]["monotonic"] + 1,
                    }
                )
            target.write_text("".join(json.dumps(r) + "\n" for r in values))
        case "racing":
            original_stat = Path.stat

            def racing_stat(path: Path, *, follow_symlinks: bool = True) -> os.stat_result:
                nonlocal calls
                result = original_stat(path, follow_symlinks=follow_symlinks)
                if path == target and follow_symlinks:
                    calls += 1
                    if calls == 2:
                        with target.open("ab") as stream:
                            stream.write(b"x")
                        return original_stat(path, follow_symlinks=follow_symlinks)
                return result

            monkeypatch.setattr(Path, "stat", racing_stat)
    destination = tmp_path / "long-w2"
    outcome = ControlResult(2, Normal(0))
    complete = publish(source, destination, outcome)
    if damage == "published-digest":
        assert complete
        path = next(destination.glob("*.jsonl"))
        path.write_bytes(path.read_bytes() + b"\n")
        with pytest.raises(UnsafeArtifact):
            exported_paths(destination)
    else:
        assert not complete
        metadata = json.loads((destination / "manifest.json").read_bytes())
        assert metadata["issues"]
        paths = exported_paths(destination)
        assert all("private-probe-not-publishable" not in Path(p).read_text() for p in paths)
        assert all("private-probe-parameter" not in Path(p).read_text() for p in paths)
        assert len(paths) <= 5
        if damage == "racing":
            assert calls == 2
