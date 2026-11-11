"""Whole-field and bounded snapshot policy controls, including the exact rejected R2 witness."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest
from artifact_policy import Sanitizer, UnsafeArtifact
from artifact_snapshot import bounded_snapshot, coverage_snapshot, records, stack_snapshot
from diagnostic_sink import Sink


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\\n", "\\r\\n"])
def test_r2_multiline_secret_is_removed_before_json(newline: str) -> None:
    # Requirement: the exact R2 multiline credential cannot survive any supported representation.
    secret = "first-private-line\nsecond-private-line"
    sanitizer = Sanitizer({"TEST_SECRET": secret})
    value = secret.replace("\n", newline)
    cleaned = sanitizer.record({"event": "collected", "nodeid": value})
    encoded = json.dumps(cleaned)
    assert secret not in encoded and value not in encoded
    assert cleaned["nodeid"] == "[redacted]"


def test_xml_escaped_newlines_are_sanitized() -> None:
    # Requirement: decoded XML attribute values use the same whole-secret policy.
    sanitizer = Sanitizer({"TEST_SECRET": "first\nsecond"})
    xml = b'<coverage><class filename="first&#10;second"/></coverage>'
    result = coverage_snapshot(xml, sanitizer)
    assert b"first" not in result and b"second" not in result
    assert b"[redacted]" in result


@pytest.mark.parametrize("environment_key", [False, True])
def test_manifest_path_is_distinct_from_environment_mapping(environment_key: bool) -> None:
    # Requirement: safe manifest paths remain publishable; recognized env dumps are refused.
    text = '{"PATH":"/bin"}' if environment_key else '{"path":"environment.jsonl"}'
    sanitizer = Sanitizer({})
    if environment_key:
        with pytest.raises(UnsafeArtifact):
            sanitizer.published(text, 4096)
    else:
        sanitizer.published(text, 4096)


@pytest.mark.parametrize("text", ["first-private-line\n", "unfinished", "\x00binary\n"])
def test_unsafe_stack_snapshot_is_withheld(text: str) -> None:
    # Requirement: an ambiguous live cutoff or unsupported stack format is never published.
    sanitizer = Sanitizer({"TEST_SECRET": "first-private-line\nsecond-private-line"})
    with pytest.raises(UnsafeArtifact):
        stack_snapshot(text.encode(), sanitizer)


def test_bounded_read_refuses_oversize(tmp_path: Path) -> None:
    # Requirement: the snapshot reader consumes at most cap+1, then withholds the artifact.
    path = tmp_path / "stack"
    path.write_bytes(b"x" * 129)
    with pytest.raises(UnsafeArtifact, match="oversize"):
        bounded_snapshot(path, 128)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"event":"collected","sequence":0,"nodeid":"x"}',
        b'{"event":"collected","sequence":2,"nodeid":"x"}\n',
        b'{"event":"collected","sequence":0,"environ":{"secret":"x"}}\n',
        b"\xff\n",
    ],
)
def test_partial_unknown_or_invalid_records_are_refused(payload: bytes) -> None:
    # Requirement: no repair/truncation can turn corrupt or untyped records into complete evidence.
    with pytest.raises((UnsafeArtifact, ValueError, UnicodeError)):
        records(payload, Sanitizer({}))


def test_short_write_produces_one_complete_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Requirement: positive short writes are completed without losing a JSONL suffix.
    sink = Sink(tmp_path / "record.jsonl", Sanitizer({}))
    original = os.write
    with monkeypatch.context() as patch:
        patch.setattr(os, "write", lambda fd, data: original(fd, data[:3]))
        assert sink.emit({"event": "collected", "nodeid": "complete-record"})
    sink.close()
    result = json.loads((tmp_path / "record.jsonl").read_text())
    assert result["nodeid"] == "complete-record"
    assert result["sequence"] == 0


@pytest.mark.parametrize("failure", ["zero", "partial", "interrupt"])
def test_write_failure_latches_with_closed_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    # Requirement: zero/partial/error writes cannot escape or append a new record to a damaged tail.
    sink = Sink(tmp_path / "record.jsonl", Sanitizer({}))
    original = os.write
    attempts = 0

    def fail_write(fd: int, data: bytes) -> int:
        nonlocal attempts
        attempts += 1
        if failure == "zero":
            return 0
        if failure == "interrupt":
            raise InterruptedError
        if attempts == 1:
            return original(fd, data[:3])
        raise OSError("synthetic")

    closed = io.StringIO()
    closed.close()
    with monkeypatch.context() as patch:
        patch.setattr(os, "write", fail_write)
        patch.setattr("sys.__stderr__", closed)
        assert sink.emit({"event": "collected", "nodeid": "first"}) is False
        assert sink.emit({"event": "collected", "nodeid": "second"}) is False
    sink.close()
    assert sink.failure is not None
    assert (tmp_path / "record.failure").exists()
    assert attempts <= 9


def test_none_stderr_and_field_cap_preserve_failure_latch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Requirement: an oversized mandatory field disables observation without raising in pytest.
    sink = Sink(tmp_path / "record.jsonl", Sanitizer({}))
    monkeypatch.setattr("sys.__stderr__", None)
    assert sink.emit({"event": "collected", "nodeid": "x" * 4097}) is False
    sink.close()
    assert sink.failure is not None
