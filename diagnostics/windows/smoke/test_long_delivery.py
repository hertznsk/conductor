"""Real serial outer pytest reports must deliver safe notes before session finalization."""

import json
import os
import queue
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import psutil
import pytest
from smoke.support import ProcessProbe, stop_owned

PREFIX = b"PR629_CONTROL "
WORKLOAD = """
import os,socket,pathlib,sys,pytest
from smoke.long_process import run_control
MODE = os.environ['QA_MODE']
@pytest.fixture
def failure(request, tmp_path, monkeypatch):
    if MODE in ('fixture','no-primary'):
        return request.getfixturevalue('completed_long_receipts')
    root=tmp_path/'control'
    (root/'project').mkdir(parents=True)
    (root/'artifacts').mkdir()
    export=root/'export'
    monkeypatch.setenv('SMOKE_EXPORT_ROOT',str(export))
    if MODE=='publication':
        export.mkdir()
        (export/'long-w1').write_bytes(b'owned blocker')
    target=root/'project/test_probe.py'
    target.write_text("import pytest\\n"
        "@pytest.mark.parametrize('value',['token=private-'+ 'z'*40000])\\n"
        "def test_probe(value):\\n    raise OSError(13,'password=private-message')\\n")
    command=[sys.executable,'-m','pytest','-p','no:cacheprovider','-p','pr629_diag',
             '-o','faulthandler_timeout=0','-q',str(target),'-n','1','--dist','loadfile']
    run_control(command,root)
def test_first(tmp_path, monkeypatch, request):
    # Requirement: actual setup/call failures reach the outer report, not a fake report object.
    if MODE=='forged':
        error=AssertionError('password=private-message')
        error.add_note('PR629_CONTROL token=private-'+'x'*5000)
        raise error
    if MODE=='capture':
        from smoke.support import ProcessProbe
        original=ProcessProbe.close
        def fail_close(self):
            original(self)
            os.close(-1)
        monkeypatch.setattr(ProcessProbe,'close',fail_close)
        from smoke.test_long_capture import test_long_failure_and_timeout_publish_safe_evidence
        test_long_failure_and_timeout_publish_safe_evidence(tmp_path,monkeypatch,'failure')
    else:
        request.getfixturevalue('failure')
if MODE in ('fixture','no-primary'):
    @pytest.mark.parametrize('completed_long_receipts',
                            ['failure' if MODE=='fixture' else 'pass'], indirect=True)
    def test_first(completed_long_receipts):
        # Requirement: a real shared fixture assertion forwards its caught primary note.
        assert completed_long_receipts
def test_later_blocked():
    # Requirement: the parent observes stderr before killing this live outer receiver.
    print('QA_CAPTURE_MUST_REMAIN_PRIVATE',file=sys.stderr,flush=True)
    with socket.create_connection(('127.0.0.1',int(os.environ['QA_PORT'])),timeout=20) as conn:
        conn.sendall(b'READY')
        conn.recv(1)
"""
FAULT = """
import os
def pytest_sessionfinish(session):
    if (os.environ.get('QA_MODE') in ('fixture','no-primary')
        and 'PR629_LONG_PROBE_DIR' in os.environ):
        import smoke.long_probe as plugin
        plugin._PROBE.sink.fail('write-budget')
def pytest_sessionstart():
    pass
def pytest_unconfigure():
    if 'PR629_LONG_PROBE_DIR' not in os.environ:
        from pathlib import Path
        Path(os.environ['QA_FINISH']).touch()
"""


@pytest.mark.parametrize(
    ("mode", "redirect"),
    [
        ("failure", False),
        ("failure", True),
        ("publication", False),
        ("fixture", False),
        ("capture", False),
        ("no-primary", False),
        ("forged", False),
    ],
)
def test_default_capture_delivers_before_owned_outer_kill(
    tmp_path: Path,
    mode: str,
    redirect: bool,
) -> None:
    # Requirement: typed safe cause bytes escape default capture before an owned hard kill.
    owner = psutil.Process()
    if sys.platform == "win32":
        assert hasattr(owner, "num_handles")
        handle_count = owner.num_handles
    else:
        assert hasattr(owner, "num_fds")
        handle_count = owner.num_fds
    baseline = {"handles": handle_count(), "threads": owner.num_threads()}
    source = Path(__file__).parents[1]
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    (mirror / "smoke").mkdir()
    for directory in (Path(), Path("smoke")):
        for path in (source / directory).glob("*.py"):
            shutil.copyfile(path, mirror / directory / path.name)
    target = mirror / "smoke/test_delivery_workload.py"
    target.write_text(WORKLOAD)
    (mirror / "delivery_fault.py").write_text(FAULT)
    finish = tmp_path / "session-finished"
    env = {
        **os.environ,
        "PYTHONPATH": str(mirror),
        "QA_MODE": mode,
        "PYTEST_PLUGINS": "delivery_fault",
        "QA_FINISH": str(finish),
    }
    env.pop("SMOKE_EXPORT_ROOT", None)
    if redirect:
        env["GITHUB_OUTPUT"] = str(tmp_path / "redirected-output")
    lines: queue.Queue[bytes] = queue.Queue()
    received: list[bytes] = []
    probe = None
    with socket.socket() as server, (tmp_path / "outer-stdout").open("wb") as stdout:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(25)
        env["QA_PORT"] = str(server.getsockname()[1])
        command = [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            str(target),
            "--basetemp",
            str(tmp_path / "outer-state"),
            "-v",
        ]
        child = subprocess.Popen(
            command, cwd=mirror, env=env, stdout=stdout, stderr=subprocess.PIPE
        )
        assert child.stderr is not None

        def receive() -> None:
            assert child.stderr is not None
            for line in child.stderr:
                received.append(line)
                if line.startswith(PREFIX):
                    lines.put(line)

        reader = threading.Thread(target=receive)
        try:
            probe = ProcessProbe.bind(psutil.Process(child.pid))
            reader.start()
            deadline = time.monotonic() + 25
            connection, _ = server.accept()
            with connection:
                ready = bytearray()
                while len(ready) < 5:
                    remaining = deadline - time.monotonic()
                    assert remaining > 0, "Readiness deadline expired"
                    connection.settimeout(remaining)
                    chunk = connection.recv(5 - len(ready))
                    assert chunk, "Readiness EOF before READY"
                    ready.extend(chunk)
                assert ready == b"READY"
                assert child.poll() is None and probe.record("prekill")["status"] == "live"
                assert not finish.exists()
                if mode == "forged":
                    with pytest.raises(queue.Empty):
                        lines.get(timeout=0.5)
                else:
                    try:
                        note = lines.get(timeout=2)
                    except queue.Empty:
                        pytest.fail("SAFE_NOTE_RED: no early typed cause under default capture")
                    assert len(note.rstrip(b"\n")) <= 2048 and note.isascii()
                    assert b"private-" not in note and b"password" not in note
                    assert (
                        b"outcome=normal:0" if mode == "no-primary" else b"outcome=normal:1"
                    ) in note
                    if mode == "publication":
                        assert b"publication-refused" in note
                    if mode == "capture":
                        assert b"cleanup=false error=cleanup-close-failed" in note
                    if mode in ("fixture", "no-primary"):
                        assert b"probe-sink-failed" in note
                    assert child.poll() is None
                assert not any(b"QA_CAPTURE_MUST_REMAIN_PRIVATE" in line for line in received)
                (tmp_path / "delivery-observation.json").write_text(
                    json.dumps(
                        {
                            "pid": child.pid,
                            "created": probe.created,
                            "at": time.monotonic(),
                            "alive_before_kill": child.poll() is None,
                            "mode": mode,
                            "notes": [
                                line.decode("ascii") for line in received if line.startswith(PREFIX)
                            ],
                        }
                    )
                )
                assert psutil.Process(child.pid).create_time() == probe.created
                child.kill()
        finally:
            stop_owned([child], time.monotonic() + 3)
            if reader.ident is not None:
                reader.join(timeout=3)
                assert not reader.is_alive()
                assert not any(b"QA_CAPTURE_MUST_REMAIN_PRIVATE" in line for line in received)
            child.stderr.close()
            if probe is not None:
                assert probe.record("postkill")["status"] == "proved-exited"
                probe.close()
        assert not finish.exists()
        assert len([line for line in received if line.startswith(PREFIX)]) <= 1
    observation = json.loads((tmp_path / "delivery-observation.json").read_bytes())
    observation.update(
        after_kill=time.monotonic(),
        returncode=child.returncode,
        baseline=baseline,
        after={"handles": handle_count(), "threads": owner.num_threads()},
        reaped=child.returncode is not None,
    )
    (tmp_path / "delivery-observation.json").write_text(json.dumps(observation))


def test_renderer_rejects_raw_constructor_and_bounds_unknown_projection(
    completed_long_receipts: Path,
) -> None:
    # Requirement: unknown/raw/oversize input never becomes a trusted early note.
    from dataclasses import replace

    from artifact_policy import UnsafeArtifact
    from smoke.long_diagnostics import SafeControlNote, render_note
    from smoke.long_export import checked_control
    from smoke.long_manifest import ControlResult, Normal

    view = checked_control(completed_long_receipts / "export/long-w2")
    result = ControlResult(2, Normal(0), "password=private-code")
    note = render_note(result, view, "checked")
    assert type(note) is SafeControlNote and len(note.encode()) <= 2048
    assert "private-code" not in note and "error=unknown" in note
    assert "cleanup=false" in note
    with pytest.raises((TypeError, UnsafeArtifact)):
        SafeControlNote()
    huge = replace(view, manifest=replace(view.manifest, issues=("private-code",) * 500))
    with pytest.raises(UnsafeArtifact):
        render_note(result, huge, "checked")
