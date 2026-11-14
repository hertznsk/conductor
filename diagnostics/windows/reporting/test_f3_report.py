"""Real two-worker controls for passive ordinary Windows reporting."""

from __future__ import annotations

import json
import os
import selectors
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from pathlib import Path
from typing import NotRequired, TypedDict

import pytest

PLUGIN = Path(__file__).resolve().parents[1]


class Event(TypedDict):
    event: str
    worker: str
    phase: NotRequired[str]
    nodeid: NotRequired[str]
    outcome: NotRequired[str]
    traceback: NotRequired[str]
    truncated: NotRequired[bool]
    stream_complete: NotRequired[bool]


def environment(root: Path, destination: Path) -> dict[str, str]:
    """Use only owned paths and no inherited CLI/provider credentials."""
    for name in ("home", "temp", "cache"):
        (root / name).mkdir(exist_ok=True)
    (root / "pytest.ini").write_text("[pytest]\n")
    return {
        "PATH": os.environ["PATH"],
        "HOME": str(root / "home"),
        "USERPROFILE": str(root / "home"),
        "TMPDIR": str(root / "temp"),
        "TEMP": str(root / "temp"),
        "TMP": str(root / "temp"),
        "XDG_CACHE_HOME": str(root / "cache"),
        "PYTHONPATH": os.pathsep.join((str(PLUGIN), str(root))),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "F3_REPORT_DIR": str(destination),
    }


def command(root: Path, observed: bool) -> list[str]:
    args = [sys.executable, "-m", "pytest", "-p", "no:cacheprovider"]
    args.extend(["-p", "xdist.plugin", "-p", "pytest_cov.plugin"])
    if observed:
        args.extend(["-p", "f3_report"])
    args.extend(["-n", "2", "--dist", "loadfile", "-c", str(root / "pytest.ini")])
    args.extend(["--confcutdir", str(root), "--junitxml", str(root / "junit.xml")])
    return args + [str(root)]


def records(destination: Path) -> list[Event]:
    return [
        json.loads(line)
        for path in destination.glob("*.jsonl")
        for line in path.read_text().splitlines()
    ]


def statuses(root: Path) -> list[tuple[str, str]]:
    return sorted(
        (case.attrib["name"], ",".join(child.tag for child in case))
        for case in ET.parse(root / "junit.xml").iter("testcase")
    )


def run(args: list[str], root: Path, env: Mapping[str, str]) -> subprocess.CompletedProcess[str]:
    """Bound each owned real pytest invocation and preserve its actual numeric exit."""
    return subprocess.run(
        args, cwd=root, env=env, capture_output=True, text=True, timeout=45, check=False
    )


def test_real_phases_tracebacks_and_outcomes_are_preserved(tmp_path: Path) -> None:
    # Requirement: real pass/capture/skip and three failure phases retain pytest's status.
    (tmp_path / "test_a.py").write_text(
        "import pytest\nimport measure\n"
        "def test_pass():\n    assert measure.add(1, 1) == 2\n"
        "def test_call():\n    assert 1 == 2, 'call-control'\n"
        "@pytest.fixture\ndef broken():\n    raise RuntimeError('setup-control')\n"
        "def test_setup(broken):\n    raise AssertionError('body-must-not-run')\n"
    )
    (tmp_path / "test_b.py").write_text(
        "import pytest\n"
        "def test_capture(capsys):\n"
        "    print('captured-only')\n"
        "    assert capsys.readouterr().out == 'captured-only\\n'\n"
        "@pytest.fixture\ndef finalizer():\n"
        "    yield\n    raise RuntimeError('teardown-control')\n"
        "def test_teardown(finalizer):\n    assert True\n"
        "@pytest.mark.skip(reason='owned skip control')\n"
        "def test_skip():\n    raise AssertionError('skip-must-not-run')\n"
    )
    (tmp_path / "measure.py").write_text("def add(a, b):\n    return a + b\n")
    destination = tmp_path / "records"
    destination.mkdir()
    env = environment(tmp_path, destination)
    coverage = ["--cov=measure", "--cov-report=xml", "--cov-report=term-missing"]
    baseline = run(command(tmp_path, False) + coverage, tmp_path, env)
    baseline_status = statuses(tmp_path)
    observed = run(command(tmp_path, True) + coverage, tmp_path, env)
    (tmp_path / "baseline.log").write_text(baseline.stdout + baseline.stderr)
    (tmp_path / "observed.log").write_text(observed.stdout + observed.stderr)
    assert baseline.returncode == observed.returncode == 1
    assert statuses(tmp_path) == baseline_status
    assert (tmp_path / "coverage.xml").exists()
    events = records(destination)
    reports = [event for event in events if event["event"] == "phase.report"]
    failures = {(r.get("phase"), r.get("outcome")) for r in reports if r.get("outcome") == "failed"}
    assert failures == {("setup", "failed"), ("call", "failed"), ("teardown", "failed")}
    assert {r["worker"] for r in reports} == {"gw0", "gw1"}
    assert {r.get("phase") for r in reports} == {"setup", "call", "teardown"}
    assert {r.get("phase") for r in events if r["event"] == "phase.begin"} == {
        "setup",
        "call",
        "teardown",
    }
    for name, phase in (("call", "call"), ("setup", "setup"), ("teardown", "teardown")):
        failure = next(
            r
            for r in reports
            if r.get("nodeid", "").endswith("::test_" + name)
            and r.get("phase") == phase
            and r.get("outcome") == "failed"
        )
        assert name + "-control" in failure.get("traceback", "")
        assert "test_" + name in failure.get("nodeid", "")
        assert observed.stdout.index(name + "-control") < observed.stdout.index(
            "short test summary"
        )
    assert not any("captured-only" in r.get("traceback", "") for r in reports)
    finishes = [r for r in events if r["event"] == "session.finish"]
    assert len(finishes) == 3 and all(r.get("stream_complete") for r in finishes)
    assert {r["worker"] for r in events if r["event"] == "worker.down"} == {"gw0", "gw1"}


@pytest.mark.skipif(os.name != "posix", reason="This kill control owns a POSIX process group.")
def test_report_is_durable_before_external_session_interruption(tmp_path: Path) -> None:
    # Requirement: an interrupted real run keeps prior failure and live phase evidence.
    (tmp_path / "test_a.py").write_text(
        "import threading\n"
        "def test_failure():\n    assert False, 'before-interruption-control'\n"
        "def test_wait():\n    threading.Event().wait()\n"
    )
    (tmp_path / "test_b.py").write_text(
        "import threading\ndef test_other_wait():\n    threading.Event().wait()\n"
    )
    destination = tmp_path / "records"
    destination.mkdir()
    env = environment(tmp_path, destination)
    lines = []
    with subprocess.Popen(
        command(tmp_path, True),
        cwd=tmp_path,
        env=env,
        start_new_session=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ) as process:
        assert process.stdout is not None
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    assert selector.select(max(0, deadline - time.monotonic()))
                    chunk = os.read(process.stdout.fileno(), 65536)
                    assert chunk
                    lines.append(chunk)
                    if any(
                        line.startswith(b"F3_REPORT ")
                        and line.endswith(b"\n")
                        and b"before-interruption-control" in line
                        for line in b"".join(lines).splitlines(keepends=True)
                    ):
                        break
                else:
                    pytest.fail("No immediate failure report before the safety deadline")
            assert process.poll() is None
            os.killpg(process.pid, signal.SIGTERM)
            tail, _ = process.communicate(timeout=10)
            lines.append(tail)
            assert process.returncode == -signal.SIGTERM
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
    (tmp_path / "interrupted.log").write_bytes(b"".join(lines))
    events = records(destination)
    assert any("before-interruption-control" in r.get("traceback", "") for r in events)
    assert any(r["event"] == "phase.begin" for r in events)
    assert not any(r["event"] == "session.finish" for r in events)
