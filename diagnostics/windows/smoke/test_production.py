"""Exercise shipped uv/pytest argv against real synthetic files, markers and coverage."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from artifact_audit import audit
from artifact_policy import COVERAGE_CAP, Sanitizer
from artifact_snapshot import bounded_snapshot
from diagnostic_sink import Sink
from smoke.long_process import run_control
from supervisor import pytest_argv

DRIVER = Path(__file__).with_name("driver.py")


@pytest.mark.parametrize(
    ("workers", "fail"), [("1", False), ("2", False), ("1", True), ("2", True)]
)
def test_production_argv_runs_selection_coverage_and_audit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    workers: str,
    fail: bool,
) -> None:
    # Requirement: the real builder controls both worker modes, markers, coverage and true outcomes.
    project = tmp_path / "project"
    project.mkdir()
    (project / "src/conductor").mkdir(parents=True)
    (project / "src/conductor/probe.py").write_text(
        "def twice(value: int) -> int:\n    return value * 2\n"
    )
    (project / "tests").mkdir()
    (project / "pyproject.toml").write_text(
        '[project]\nname="diagnostic-synthetic"\nversion="0.0.0"\nrequires-python=">=3.13"\n'
        '[tool.pytest.ini_options]\ntestpaths=["tests"]\n'
        'markers=["real_api","install_scripts","performance","docker_integration"]\n'
    )
    for suffix in ("a", "b"):
        (project / f"tests/test_{suffix}.py").write_text(
            "import os, runpy\n"
            f"def test_{suffix}():\n"
            "    value = runpy.run_path('src/conductor/probe.py')['twice'](3)\n"
            "    assert value == 6\n"
            f"    should_fail = os.environ.get('DIAG_SMOKE_FAIL') == '1' and '{suffix}' == 'a'\n"
            "    assert not should_fail\n"
        )
    (project / "tests/test_excluded.py").write_text(
        "import pytest\n"
        + "\n".join(
            f"@pytest.mark.{marker}\ndef test_{marker}():\n"
            "    raise AssertionError('excluded marker executed')\n"
            for marker in ("real_api", "install_scripts", "performance", "docker_integration")
        )
    )
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    monkeypatch.setenv("UV_PROJECT_ENVIRONMENT", sys.prefix)
    monkeypatch.setenv("UV_NO_SYNC", "1")
    monkeypatch.setenv("UV_OFFLINE", "1")
    monkeypatch.setenv("DIAG_SMOKE_FAIL", "1" if fail else "0")
    result = subprocess.run(
        [sys.executable, str(DRIVER), str(artifacts), "production", workers],
        cwd=project,
        stdout=None,
        stderr=None,
        timeout=30,
        check=False,
    )
    output = capfd.readouterr()
    assert result.returncode == (1 if fail else 0), output.err
    assert "TOTAL" in output.out and "slowest" in output.out
    assert ("1 failed" if fail else "2 passed") in output.out
    xml = bounded_snapshot(project / "coverage.xml", COVERAGE_CAP)
    assert b'hits="1"' in xml and b"probe.py" in xml
    (artifacts / "coverage.xml").write_bytes(xml)
    phases = [
        [json.loads(line) for line in path.read_text().splitlines()]
        for path in artifacts.glob("*.phase.jsonl")
    ]
    assert len(phases) == int(workers) + 1
    configured = next(
        r
        for events in phases
        for r in events
        if r["event"] == "configured" and r["worker"] == "controller"
    )
    assert configured["numprocesses"] == int(workers)
    assert configured["dist"] == "loadfile"
    assert configured["durations"] == 200 and configured["durations_min"] == 0.5
    assert configured["verbosity"] >= 1 and configured["cacheprovider"] is False
    assert configured["faulthandler_zero"] is True
    assert configured["cov_source"] == ["src/conductor"]
    for events in phases:
        assert not any("test_excluded" in event.get("label", "") for event in events)
        assert all("nodeid" not in event for event in events)
        assert [r["item_index"] for r in events if r["event"] == "collected"] == [0, 1]
        assert all(
            isinstance(r["duration"], (int, float)) for r in events if r["event"] == "report"
        )
    executed = {
        events[0]["worker"]
        for events in phases
        if events[0]["worker"] != "controller"
        and any(event["event"] == "call.begin" for event in events)
    }
    assert len(executed) == int(workers)
    # Synthetic provenance is named honestly; it never substitutes for the setup receipt on S.
    environment = Sink(artifacts / "environment.jsonl", Sanitizer({}))
    environment.emit(
        {
            "event": "environment",
            "scope": "synthetic-project",
            "argv": pytest_argv(workers),
            "python": sys.version,
        }
    )
    environment.close()
    step = Sink(artifacts / "step.jsonl", Sanitizer({}))
    step.emit({"event": "step", "outcome": "failure" if fail else "success", "interrupted": False})
    step.close()
    staging = tmp_path / "published"
    evidence_ok = audit(artifacts, staging)
    manifest = json.loads((staging / "manifest.json").read_text())
    if export := os.environ.get("SMOKE_EXPORT_ROOT"):
        destination = Path(export) / f"w{workers}-{'fail' if fail else 'pass'}"
        destination.mkdir(parents=True)
        for entry in manifest["artifacts"]:
            if entry["status"] == "complete":
                shutil.copyfile(staging / entry["path"], destination / entry["path"])
        shutil.copyfile(staging / "manifest.json", destination / "manifest.json")
    assert evidence_ok, manifest
    assert manifest["root_outcome"]["root_code"] == result.returncode
    assert manifest["raw_channel"]["uploaded_as_diagnostic_artifact"] is False
    assert manifest["raw_channel"]["service_redaction"] == "not_performed"
    assert set(manifest["comparison_evidence"]) == {"resources", "timing"}
    assert manifest["comparison_evidence"]["resources"]["status"] == "insufficient-samples"
    for name in ("resource-summary.json", "timing-summary.json"):
        assert 0 < (staging / name).stat().st_size <= 1024 * 1024
    assert not any(
        "stdout" in item["path"] or "stderr" in item["path"] for item in manifest["artifacts"]
    )
    # A missing mandatory phase must fail the independent audit without changing root outcome.
    broken = tmp_path / "broken"
    broken.mkdir()
    for path in artifacts.iterdir():
        if path.is_file() and not path.name.endswith(".phase.jsonl"):
            shutil.copyfile(path, broken / path.name)
    assert audit(broken, tmp_path / "refused") is False
    assert (
        json.loads((tmp_path / "refused/manifest.json").read_text())["root_outcome"]["root_code"]
        == result.returncode
    )


@pytest.mark.parametrize("workers", ["1", "2"])
def test_long_parameter_cannot_cut_off_following_test(tmp_path: Path, workers: str) -> None:
    # Requirement: long secret-like parameters never enter diagnostics or stop subsequent records.
    project = tmp_path / "project"
    project.mkdir()
    target = project / "test_long.py"
    (project / "pytest.ini").write_text(
        "[pytest]\ndisable_test_id_escaping_and_forfeit_all_rights_to_community_support=True\n"
    )
    target.write_text(
        "import pytest\n"
        "@pytest.mark.parametrize('value', ['token=private-' + 'q' * 40000, *range(7228)],"
        f"ids=['token=private-id-' + {ascii(chr(0x4E00))}*11000, *map(str,range(7228))])\n"
        "def test_parameter(value, request):\n    assert value is not None\n"
        "    if isinstance(value,str):\n"
        "        assert value == 'token=private-' + 'q'*40000\n"
        "        assert len(request.node.nodeid.encode('utf-8')) > 32*1024\n"
        "        full='PYTEST_CURRENT_TEST='+request.node.nodeid+' (teardown)'\n"
        "        assert len(full.encode('utf-16-le'))//2 < 16000\n"
        "def test_following():\n    assert True\n"
    )
    (project / "test_more.py").write_text(
        "import pytest\n@pytest.mark.parametrize('value', range(7229))\n"
        "def test_more(value):\n    assert value >= 0\n"
    )
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    result = run_control(
        [
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
            str(project / "test_more.py"),
            "-n",
            workers,
            "--dist",
            "loadfile",
        ],
        tmp_path,
    )
    assert result.returncode == 0
    for phase in artifacts.glob("*.phase.jsonl"):
        events = [json.loads(line) for line in phase.read_text().splitlines()]
        assert events[-1]["event"] == "unconfigure.end"
        assert sum(r["event"] == "collected" for r in events) == 14459
        assert [r["item_index"] for r in events if r["event"] == "collected"] == list(range(14459))
        if events[0]["worker"] == "controller":
            assert sum(r["event"] == "report" and r["phase"] == "teardown" for r in events) == 14459
        assert "private-" not in phase.read_text() and "q" * 4096 not in phase.read_text()
    assert not list(artifacts.glob("*.failure"))


@pytest.mark.parametrize("fault", ["mismatch", "overflow"])
def test_collection_identity_refuses_mismatch_and_overflow(tmp_path: Path, fault: str) -> None:
    # Requirement: unequal collections and oversized identity tables cannot claim completeness.
    program = (
        "import pr629_diag as p,sys;"
        "p.OBSERVATION.collect(['test_a.py::test_a[token=private-parameter]']);"
        "p.OBSERVATION.collect(['test_a.py::test_b'] if sys.argv[1]=='mismatch' else ['x']*65537);"
        "assert p.OBSERVATION.sink.failure is not None"
    )
    result = subprocess.run(
        [sys.executable, "-c", program, fault],
        env={**os.environ, "PR629_DIAG_DIR": str(tmp_path)},
        timeout=5,
        check=False,
    )
    assert result.returncode == 0
    phase = next(tmp_path.glob("*.phase.jsonl"))
    text = phase.read_text()
    events = [json.loads(line) for line in text.splitlines()]
    assert events[-1]["reason"] == "collection-" + ("mismatch" if fault == "mismatch" else "budget")
    assert "private-parameter" not in text and "nodeid" not in text
