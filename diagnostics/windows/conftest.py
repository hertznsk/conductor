"""Keep nested pytest/xdist state inside the explicitly selected smoke basetemp."""

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

import pytest
from artifact_policy import MIB, SCHEMA, environment_sanitizer
from diagnostic_sink import Sink

_smoke_report: Sink | None = None


@pytest.fixture(autouse=True)
def isolated_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    temp = tmp_path / "temp"
    home.mkdir()
    temp.mkdir()
    for key in ("HOME", "USERPROFILE", "XDG_CACHE_HOME"):
        monkeypatch.setenv(key, str(home))
    for key in ("TMPDIR", "TMP", "TEMP"):
        monkeypatch.setenv(key, str(temp))
    monkeypatch.setattr(tempfile, "tempdir", str(temp))
    monkeypatch.setenv("GITHUB_ENV", str(tmp_path / "github-env"))
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "github-output"))
    # Synthetic workloads have no reason to inherit real provider credentials.
    for name in tuple(os.environ):
        if re.search(r"(?:TOKEN|PASSWORD|SECRET|API_KEY)", name, re.I):
            monkeypatch.delenv(name)


def pytest_sessionstart() -> None:
    global _smoke_report
    if destination := os.environ.get("SMOKE_EXPORT_ROOT"):
        root = Path(destination)
        root.mkdir(exist_ok=True)
        _smoke_report = Sink(root / "smoke-report.jsonl", environment_sanitizer(), MIB)


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    if _smoke_report is not None:
        _smoke_report.emit(
            {
                "event": "report",
                "nodeid": report.nodeid,
                "phase": report.when,
                "outcome": report.outcome,
            }
        )


def pytest_sessionfinish() -> None:
    if _smoke_report is None:
        return
    _smoke_report.close()
    root = Path(os.environ["SMOKE_EXPORT_ROOT"])
    paths = [str(root / "smoke-report.jsonl")]
    for topology in ("parent", "chain"):
        for mode in ("natural", "live", "interrupted"):
            receipt = root / f"peer-{topology}-{mode}.jsonl"
            if receipt.exists():
                digest = receipt.with_suffix(".sha256")
                assert (
                    digest.read_text().strip() == hashlib.sha256(receipt.read_bytes()).hexdigest()
                )
                paths.extend((str(receipt), str(digest)))
    for case in ("w1-pass", "w2-pass", "w1-fail", "w2-fail"):
        manifest_path = root / case / "manifest.json"
        if not manifest_path.exists():
            continue
        manifest = json.loads(manifest_path.read_text())
        assert manifest["schema"] == SCHEMA
        for artifact in manifest["artifacts"]:
            name = artifact["path"]
            assert re.fullmatch(
                r"\d+-(?:controller|gw\d+)\.(?:phase\.jsonl|stack\.txt)|"
                r"(?:environment|supervisor|processes|post-root|step)\.jsonl|coverage\.xml",
                name,
            )
            if artifact["status"] == "complete":
                paths.append(str(root / case / name))
        paths.append(str(manifest_path))
    if destination := os.environ.get("GITHUB_OUTPUT"):
        with Path(destination).open("a", encoding="utf-8") as stream:
            stream.write("paths<<SMOKE_PATHS\n" + "\n".join(paths) + "\nSMOKE_PATHS\n")
