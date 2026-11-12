"""Actual OLD/NEW pytest environment-boundary proof, independent of ownership adoption."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest
from artifact_policy import Sanitizer
from smoke.long_records import control_records
from smoke.support import ProcessProbe, stop_owned, wait_until

INI = "[pytest]\ndisable_test_id_escaping_and_forfeit_all_rights_to_community_support=True\n"
COLLECTION = """
import json,os,pathlib
def pytest_collection_finish(session):
    values=[]
    for item in session.items:
        parameter=item.callspec.params['value']
        values.append({
            'node_bytes':len(item.nodeid.encode('utf-8')),
            'env_units':len(('PYTEST_CURRENT_TEST='+item.nodeid
                            +' (teardown)').encode('utf-16-le'))//2,
            'value_length':len(parameter),
            'value_preserved':parameter=='token=private-parameter'+'z'*40000,
        })
    role=os.environ.get('PYTEST_XDIST_WORKER','controller')
    pathlib.Path('lengths-'+role+'.json').write_text(json.dumps(values))
"""


@pytest.mark.parametrize("representation", ["old", "new"])
@pytest.mark.parametrize("body", ["failure", "timeout"])
def test_actual_platform_identity_and_intended_phase(
    tmp_path: Path,
    representation: str,
    body: str,
) -> None:
    # Requirement: equal config/value differ only in ID; Windows OLD must fail before the body.
    project = tmp_path / "project"
    project.mkdir()
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    compact = tmp_path / "compact"
    compact.mkdir()
    (project / "pytest.ini").write_text(INI)
    (project / "conftest.py").write_text(COLLECTION)
    ids = (
        ""
        if representation == "old"
        else (f",ids=['token=private-id-'+{ascii(chr(0x4E00))}*11000]")
    )
    target = project / "test_probe.py"
    action = (
        "    raise OSError(13,'password=private-call')\n"
        if body == "failure"
        else "    threading.Event().wait(2)\n"
    )
    target.write_text(
        "import pathlib,threading,pytest\n"
        "@pytest.mark.parametrize('value',['token=private-parameter'+'z'*40000]" + ids + ")\n"
        "def test_probe(value):\n"
        "    assert value=='token=private-parameter'+'z'*40000\n"
        "    pathlib.Path('body.ready').touch()\n" + action
    )
    env = {**os.environ, "PR629_DIAG_DIR": str(artifacts), "PR629_LONG_PROBE_DIR": str(compact)}
    argv = [
        sys.executable,
        "-m",
        "pytest",
        "-p",
        "no:cacheprovider",
        "-p",
        "pr629_diag",
        "-p",
        "smoke.long_probe",
        "-o",
        "faulthandler_timeout=0",
        "-q",
        str(target),
        "-n",
        "1",
        "--dist",
        "loadfile",
        "--basetemp",
        str(tmp_path / "nested-state"),
    ]
    child = subprocess.Popen(argv, cwd=project, env=env, stdout=subprocess.DEVNULL)
    probe = None
    timed_out = False
    try:
        probe = ProcessProbe.bind(psutil.Process(child.pid))
        wait_until(
            lambda: (project / "body.ready").exists() or child.poll() is not None,
            time.monotonic() + 12,
        )
        if body == "timeout" and (project / "body.ready").exists():
            with pytest.raises(subprocess.TimeoutExpired):
                child.wait(timeout=0.05)
            timed_out = True
        code = child.wait(timeout=12)
    finally:
        stop_owned([child], time.monotonic() + 3)
        if probe is not None:
            assert probe.record("reaped")["status"] == "proved-exited"
            probe.close()
    lengths = json.loads((project / "lengths-gw0.json").read_bytes())
    assert len(lengths) == 1 and lengths[0]["value_preserved"] is True
    assert lengths[0]["value_length"] == len("token=private-parameter") + 40000
    assert lengths[0]["node_bytes"] > 32 * 1024
    if representation == "new":
        assert lengths[0]["env_units"] < 16000
    else:
        assert lengths[0]["env_units"] > 32767
    parsed = [control_records(path.read_bytes(), Sanitizer({})) for path in compact.glob("*.jsonl")]
    worker = next(p for p in parsed if p.startup.role == "gw0")
    records = [json.loads(line) for line in worker.content.splitlines()]
    headers = [r for r in records if r["kind"] == "exception"]
    ready = (project / "body.ready").exists()
    if sys.platform == "win32" and representation == "old":
        assert not ready and not timed_out and code != 0
        assert any(r["exception_type"] == "ValueError" and r["phase"] == "setup" for r in headers)
    else:
        assert ready
        assert not any(r["phase"] == "setup" for r in headers)
        if body == "failure":
            assert code == 1 and not timed_out
            assert any(
                r["exception_type"] == "PermissionError"
                and r["errno"] == 13
                and r["phase"] == "call"
                for r in headers
            )
        else:
            assert code == 0 and timed_out
    assert all(b"private-" not in p.content and b"z" * 4096 not in p.content for p in parsed)
    (tmp_path / "numeric-proof.json").write_text(
        json.dumps(
            {
                "platform": sys.platform,
                "representation": representation,
                "body": body,
                "lengths": lengths,
                "root_code": code,
                "wait_timeout": timed_out,
                "body_ready": ready,
                "ownership": "not-measured",
                "headers": [
                    {k: r[k] for k in ("exception_type", "phase", "errno", "winerror")}
                    for r in headers
                ],
                "identities": [
                    {"pid": p.startup.pid, "created": p.startup.created, "role": p.startup.role}
                    for p in parsed
                ],
            }
        )
    )
