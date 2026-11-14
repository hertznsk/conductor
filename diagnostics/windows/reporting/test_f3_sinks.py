"""Real two-worker controls for truncated and unusable reporting sinks."""

import json
from pathlib import Path

import pytest
from diagnostics.windows.reporting.test_f3_report import command, environment, records, run


@pytest.mark.parametrize(
    "mode",
    ["truncated", "caps"]
    + [
        f"{writer}-{outcome}"
        for writer in ("write", "stdout", "zero", "prefix", "zero-notice", "prefix-notice")
        for outcome in ("pass", "fail")
    ],
)
def test_bounded_or_unavailable_reporting_keeps_real_exit(tmp_path: Path, mode: str) -> None:
    # Requirement: raised/short sink writes mark incomplete evidence, preserving real exits.
    destination = tmp_path / "records"
    env = environment(tmp_path, destination)
    failing = not mode.endswith("pass")
    id_length = 2000 if mode == "truncated" else 1
    trace_length = 20000 if mode == "truncated" else 1
    (tmp_path / "test_control.py").write_text(
        "import pytest\n"
        f"@pytest.mark.parametrize('value', [1], ids=['x' * {id_length}])\n"
        "def test_control(value):\n"
        + (
            f"    assert False, 'trace-head-' + 'z' * {trace_length} + '-trace-tail'\n"
            if failing
            else "    assert value == 1\n"
        )
    )
    if mode.startswith("write-"):
        destination.write_text("not a directory")
    else:
        destination.mkdir()
    if mode == "caps":
        (tmp_path / "conftest.py").write_text(
            "import f3_report\nf3_report.FILE_CAP = 800\nf3_report.STDOUT_CAP = 800\n"
        )
    short = mode.startswith(("zero-", "prefix-"))
    width = 0 if mode.startswith("zero-") else 7
    ledger = tmp_path / "sink-writes.jsonl"
    if mode.startswith("stdout-") or short:
        (tmp_path / "conftest.py").write_text(
            "import sys,json\n"
            "class Broken:\n"
            "    def __init__(self, channel):\n        self.channel = channel\n"
            "    def write(self, value):\n"
            f"        limit = {width if short else -1}\n"
            "        if limit < 0:\n            raise OSError('owned stdout failure')\n"
            "        part = value[:limit]\n"
            f"        with open({str(ledger)!r}, 'a', encoding='utf8') as stream:\n"
            "            stream.write(json.dumps("
            "{'channel': self.channel, 'text': part}) + '\\n')\n"
            "        return len(part)\n"
            "    def flush(self):\n        pass\n"
            "def pytest_sessionstart(session):\n"
            "    if not hasattr(session.config, 'workerinput'):\n"
            "        sys.__stdout__ = Broken('stdout')\n"
            + ("        sys.__stderr__ = Broken('stderr')\n" if "-notice-" in mode else "")
        )
    result = run(command(tmp_path, True), tmp_path, env)
    (tmp_path / "observed.log").write_text(result.stdout + result.stderr)
    assert result.returncode == int(failing)
    if mode == "truncated":
        events = records(destination)
        failure = next(r for r in events if r.get("outcome") == "failed")
        assert failure.get("truncated")
        assert len(failure.get("nodeid", "")) <= 1024
        assert len(failure.get("traceback", "")) <= 8192
        assert "[truncated]" in failure.get("traceback", "")
        assert "trace-tail" in failure.get("traceback", "")
        finishes = [r for r in events if r["event"] == "session.finish"]
        # One file runs on one worker; its stream and the controller see truncation.
        assert sum(r.get("stream_complete") is False for r in finishes) == 2
        assert sum(r.get("stream_complete") is True for r in finishes) == 1
    elif "-notice-" not in mode:
        assert "F3_REPORT_INCOMPLETE" in result.stdout + result.stderr
    if mode == "caps":
        assert all(path.stat().st_size <= 800 for path in destination.glob("*.jsonl"))
        assert list(destination.glob("*.incomplete"))
        lines = [line for line in result.stdout.splitlines() if line.startswith("F3_REPORT ")]
        assert sum(len(line) + 2 for line in lines) <= 800
    if short:
        latch = (destination / "reporting.incomplete").read_text()
        assert "stdout-write" in latch
        assert ("stderr-write" in latch) == ("-notice-" in mode)
        attempts = [json.loads(line) for line in ledger.read_text().splitlines()]
        expected = [("stdout", width)] + ([("stderr", width)] if "-notice-" in mode else [])
        assert [(a["channel"], len(a["text"])) for a in attempts] == expected
        finishes = [
            r
            for r in records(destination)
            if r["worker"] == "controller" and r["event"] == "session.finish"
        ]
        assert [r.get("stream_complete") for r in finishes] == [False]
