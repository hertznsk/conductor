"""Real failed and bounded-timeout capture regression cases."""

import json
import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest
from smoke.long_diagnostics import transfer_note
from smoke.long_process import run_control
from smoke.support import ProcessProbe, stop_owned


@pytest.mark.parametrize("mode", ["failure", "timeout"])
def test_long_failure_and_timeout_publish_safe_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    # Requirement: real nested failures/timeouts export safe evidence before raising.
    project = tmp_path / "project"
    project.mkdir()
    (tmp_path / "artifacts").mkdir()
    export = tmp_path / "export"
    monkeypatch.setenv("SMOKE_EXPORT_ROOT", str(export))
    (project / "conftest.py").write_text(
        "import json,os,pathlib,psutil\n"
        "def pytest_sessionstart():\n"
        " p=psutil.Process();role=os.environ.get('PYTEST_XDIST_WORKER','controller')\n"
        " pathlib.Path(role+'.qa-ready.json').write_text(json.dumps("
        "{'pid':p.pid,'created':p.create_time()}))\n"
    )
    target = project / "test_probe.py"
    (project / "pytest.ini").write_text(
        "[pytest]\ndisable_test_id_escaping_and_forfeit_all_rights_to_community_support=True\n"
    )
    body = (
        "    raise OSError(13, 'password=private-probe-exception')\n"
        if mode == "failure"
        else "    pathlib.Path('body.ready').touch()\n    threading.Event().wait(30)\n"
    )
    target.write_text(
        "import pathlib,threading,pytest\n"
        "@pytest.mark.parametrize('value',['token=private-probe-parameter'+'z'*40000],"
        f"ids=['token=private-id-'+{ascii(chr(0x4E00))}*11000])\n"
        "def test_probe(value):\n" + body + "@pytest.fixture(autouse=True)\n"
        "def check_identity(request):\n"
        "    assert request.node.callspec.params['value']=="
        "'token=private-probe-parameter'+'z'*40000\n"
        "    assert len(request.node.nodeid.encode('utf-8')) > 32*1024\n"
        "    full='PYTEST_CURRENT_TEST='+request.node.nodeid+' (teardown)'\n"
        "    assert len(full.encode('utf-16-le'))//2 < 16000\n"
    )
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
    probes: list[ProcessProbe] = []
    primary: BaseException | None = None
    try:
        expected_error = AssertionError if mode == "failure" else subprocess.TimeoutExpired
        with pytest.raises(expected_error) as caught:
            result = run_control(command, tmp_path, 5)
            assert result.returncode == 0
        primary = caught.value
        manifest = export / "long-w2" / "manifest.json"
        assert manifest.is_file(), "Failed long control lost its evidence before assertion."
        metadata = json.loads(manifest.read_bytes())
        assert metadata["root_code"] == (1 if mode == "failure" else None)
        assert metadata["timeout"] is (mode == "timeout")
        assert metadata["cleanup_complete"]
        published = list(manifest.parent.glob("*.jsonl"))
        assert len(published) == 3
        contents = b"".join(p.read_bytes() for p in published)
        assert b"private-probe" not in contents and b"z" * 4096 not in contents
        assert b'"item_index"' not in contents and b'"label"' not in contents
        if mode == "failure":
            assert b'"exception_type": "PermissionError"' in contents
            frames = [
                json.loads(line) for path in published for line in path.read_bytes().splitlines()
            ]
            assert any(
                r.get("path") == "test_probe.py"
                and r.get("name") == "test_probe"
                and r.get("ident") == 4
                for r in frames
            )
        else:
            assert (project / "body.ready").exists()
        for path in project.glob("*.qa-ready.json"):
            birth = json.loads(path.read_bytes())
            if psutil.pid_exists(birth["pid"]):
                process = psutil.Process(birth["pid"])
                assert (
                    process.create_time() != birth["created"]
                    or process.status() == psutil.STATUS_ZOMBIE
                )
    except (AssertionError, OSError) as secondary:
        transfer_note(primary, secondary)
        raise
    finally:
        # Rescue a genuine pre-instrumentation RED using only early fixture-owned birth receipts.
        for path in project.glob("*.qa-ready.json"):
            birth = json.loads(path.read_bytes())
            try:
                process = psutil.Process(birth["pid"])
                if process.create_time() == birth["created"]:
                    probes.append(ProcessProbe.bind(process))
            except psutil.NoSuchProcess:
                continue
        try:
            stop_owned([], time.monotonic() + 3, [p.process for p in probes])
        finally:
            for probe in probes:
                probe.close()


def test_long_probe_bounds_actual_exception_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Requirement: ten real xdist failures retain only eight safe exception details per process.
    project = tmp_path / "project"
    project.mkdir()
    (tmp_path / "artifacts").mkdir()
    monkeypatch.setenv("SMOKE_EXPORT_ROOT", str(tmp_path / "export"))
    target = project / "test_probe.py"
    target.write_text(
        "import pytest\n@pytest.mark.parametrize('value',range(10))\n"
        "def test_probe(value):\n    raise RuntimeError('password=private-probe-many-errors')\n"
    )
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
    with pytest.raises(AssertionError):
        run_control(command, tmp_path)
    outputs = list((tmp_path / "export/long-w2").glob("*.jsonl"))
    assert len(outputs) == 3
    runtime_errors = 0
    for path in outputs:
        values = [json.loads(line) for line in path.read_bytes().splitlines()]
        headers = [r for r in values if r["kind"] == "exception"]
        assert len(headers) <= 8
        assert all(r.get("known", 0) <= 8 for r in values if r["kind"] == "frame")
        runtime_errors += sum(r["exception_type"] == "RuntimeError" for r in headers)
        assert b"private-probe" not in path.read_bytes()
        if headers:
            assert max(r.get("omitted", 0) for r in values if r["kind"] == "main-sink") == 2
    assert runtime_errors == 8
