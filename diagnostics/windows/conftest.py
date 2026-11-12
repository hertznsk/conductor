"""Keep nested pytest/xdist state inside the explicitly selected smoke basetemp."""

import hashlib
import json
import os
import re
import sys
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest
from _pytest.capture import CaptureManager
from artifact_policy import MIB, SCHEMA, environment_sanitizer
from diagnostic_sink import Sink
from smoke.long_diagnostics import control_note, transfer_note
from smoke.long_export import exported_paths
from smoke.long_process import run_control

_smoke_report: Sink | None = None
_smoke_output: str | None = None


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
    global _smoke_report, _smoke_output
    _smoke_report = None
    _smoke_output = os.environ.get("GITHUB_OUTPUT")
    if destination := os.environ.get("SMOKE_EXPORT_ROOT"):
        root = Path(destination)
        root.mkdir(exist_ok=True)
        _smoke_report = Sink(root / "smoke-report.jsonl", environment_sanitizer(), MIB)
        # Keep the bounded report reachable even if final export cannot finish.
        if _smoke_output and _smoke_report.fd is not None:
            with Path(_smoke_output).open("a", encoding="utf-8") as stream:
                stream.write(f"paths<<SMOKE_PATHS\n{_smoke_report.path}\nSMOKE_PATHS\n")


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
    global _smoke_report, _smoke_output
    report, output = _smoke_report, _smoke_output
    _smoke_report, _smoke_output = None, None
    if report is None:
        return
    report.close()
    root = report.path.parent
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
                r"(?:environment|supervisor|processes|post-root|step)\.jsonl|coverage\.xml|"
                r"(?:resource|timing)-summary\.json",
                name,
            )
            if artifact["status"] == "complete":
                paths.append(str(root / case / name))
        paths.append(str(manifest_path))
    long_paths = []
    for case in ("long-w1", "long-w2"):
        destination = root / case
        if (destination / "manifest.json").exists():
            long_paths.extend(exported_paths(destination))
    assert sum(Path(path).stat().st_size for path in long_paths) <= MIB
    assert sum(path.endswith(".jsonl") for path in long_paths) <= 8
    paths.extend(long_paths)
    if output:
        with Path(output).open("a", encoding="utf-8") as stream:
            stream.write("paths<<SMOKE_PATHS\n" + "\n".join(paths) + "\nSMOKE_PATHS\n")


@pytest.fixture(scope="module")
def completed_long_receipts(
    tmp_path_factory: pytest.TempPathFactory, request: pytest.FixtureRequest
) -> Path:
    mode = getattr(request, "param", "pass")
    code = {"pass": 0, "failure": 1, "internal": 3}[mode]
    root = tmp_path_factory.mktemp("completed-long-" + mode)
    (root / "project").mkdir()
    (root / "artifacts").mkdir()
    (root / "home").mkdir()
    (root / "temp").mkdir()
    target = root / "project" / "test_probe.py"
    target.write_text("def test_probe():\n    assert 2 + 2 == 4\n")
    if mode == "failure":
        target.write_text(
            "def test_probe():\n    raise OSError(13, 'password=private-probe-error')\n"
        )
    if mode == "internal":
        (root / "project/conftest.py").write_text(
            "def pytest_collection_modifyitems(config):\n"
            "    if hasattr(config,'workerinput'):\n"
            "        raise OSError(13,'password=private-probe-internal')\n"
        )
    primary: BaseException | None = None
    with pytest.MonkeyPatch.context() as patch:
        for key in tuple(os.environ):
            if re.search(r"(?:TOKEN|PASSWORD|SECRET|API_KEY|CREDENTIAL|AUTH)", key, re.I):
                patch.delenv(key)
        for key in ("GITHUB_ENV", "GITHUB_OUTPUT"):
            patch.setenv(key, str(root / key.lower()))
        for key in ("XDG_CONFIG_HOME", "XDG_DATA_HOME"):
            patch.setenv(key, str(root / "home"))
        for key in ("HOME", "USERPROFILE", "XDG_CACHE_HOME"):
            patch.setenv(key, str(root / "home"))
        for key in ("TMPDIR", "TMP", "TEMP"):
            patch.setenv(key, str(root / "temp"))
        patch.setenv("SMOKE_EXPORT_ROOT", str(root / "export"))
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
        if code == 0:
            assert run_control(command, root).returncode == 0
        else:
            with pytest.raises(AssertionError, match=f"exited with code {code}") as caught:
                run_control(command, root)
            primary = caught.value
    try:
        metadata = json.loads((root / "export/long-w2/manifest.json").read_bytes())
        assert metadata["root_code"] == code and metadata["complete"] is True
    except (AssertionError, OSError) as secondary:
        transfer_note(primary, secondary)
        raise
    return root


@pytest.hookimpl(wrapper=True, trylast=True)
def pytest_runtest_makereport(
    item: pytest.Item, call: pytest.CallInfo[None]
) -> Generator[None, pytest.TestReport, pytest.TestReport]:
    report = yield
    if report.failed and report.when in ("setup", "call") and call.excinfo is not None:
        error = call.excinfo.value
        note = control_note(error)
        capture = item.config.pluginmanager.getplugin("capturemanager")
        if note is not None and isinstance(capture, CaptureManager):
            with capture.global_and_fixture_disabled():
                try:
                    print(note, file=sys.stderr, flush=True)
                except (OSError, ValueError):
                    error.add_note("Safe control stderr unavailable.")
    return report
