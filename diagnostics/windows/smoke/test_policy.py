"""Whole-field and bounded snapshot policy controls, including the exact rejected R2 witness."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path

import pytest
from artifact_policy import Sanitizer, UnsafeArtifact
from artifact_snapshot import (
    bounded_snapshot,
    coverage_snapshot,
    prefix_records,
    records,
    stack_snapshot,
)
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


@pytest.mark.parametrize(
    "tail,reason",
    [
        (b'{"event":', "partial-jsonl-tail"),
        (b"bad\n", "invalid-json"),
        (b'{"event":"host","sequence":3,"monotonic":2}\n', "sequence-gap"),
        (b'{"event":"host","sequence":1,"monotonic":0}\n', "timestamp-order"),
        (b'{"event":"host","sequence":1,"monotonic":2,"handle":123}\n', "unknown-field"),
    ],
)
def test_prefix_stops_at_first_invalid_record(
    tmp_path: Path,
    tail: bytes,
    reason: str,
) -> None:
    # Requirement: corrupt/gapped/truncated streams keep only the sequential prefix, never a repair.
    valid = b'{"event":"host","sequence":0,"monotonic":1}\n'
    path = tmp_path / "prefix.jsonl"
    path.write_bytes(
        valid + tail + b'{"event":"exit","sequence":2,"monotonic":3}\n'
        if reason != "partial-jsonl-tail"
        else valid + tail
    )
    result = prefix_records(path, Sanitizer({}))
    assert result.content == valid and result.records_consumed == 1
    assert result.validated_bytes == len(valid)
    assert result.discarded_tail_bytes == path.stat().st_size - len(valid)
    assert result.error_counts == {reason: 1}
    assert result.sha256 == hashlib.sha256(valid).hexdigest()
    assert result.right_censored and not result.terminal_event_seen
    with pytest.raises(UnsafeArtifact):
        records(path.read_bytes(), Sanitizer({}))


def test_prefix_race_discards_entire_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Requirement: racing metadata invalidates all measurements with one read and no retry.
    path = tmp_path / "racing.jsonl"
    path.write_bytes(b'{"event":"host","sequence":0,"monotonic":1}\n')
    original = Path.stat
    calls = 0

    def racing_stat(target: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        nonlocal calls
        result = original(target, follow_symlinks=follow_symlinks)
        if target == path and follow_symlinks:
            calls += 1
            if calls == 2:
                with path.open("ab") as stream:
                    stream.write(b"x")
                result = original(target, follow_symlinks=follow_symlinks)
        return result

    monkeypatch.setattr(Path, "stat", racing_stat)
    result = prefix_records(path, Sanitizer({}))
    assert calls == 2 and not result.content
    assert result.measurement_status == "unavailable"
    assert result.error_counts == {"racing-snapshot": 1}


def test_prefix_byte_cap_preserves_only_valid_bounded_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Requirement: the input cap is a censor boundary, not permission to publish oversized input.
    path = tmp_path / "capped.jsonl"
    valid = b'{"event":"host","sequence":0,"monotonic":1}\n'
    path.write_bytes(valid * 2)
    monkeypatch.setattr("artifact_snapshot.LOG_CAP", len(valid))
    result = prefix_records(path, Sanitizer({}))
    assert result.content == valid and result.error_counts == {"input-cap": 1}
    assert result.discarded_tail_bytes == len(valid) and result.right_censored


@pytest.mark.parametrize(
    "field,value", [("error", "private"), ("handle", 123), ("exception_type", "SecretCustomError")]
)
def test_close_error_policy_refuses_raw_exception_fields(field: str, value: str | int) -> None:
    # Requirement: close failures exclude exception text, native handles and arbitrary classes.
    raw = {
        "event": "process.close_error",
        "stage": "finish",
        "reason": "process-handle-close-failed",
        "exception_type": "OSError",
        field: value,
    }
    with pytest.raises(UnsafeArtifact, match="invalid-close-error"):
        Sanitizer({}).record(raw)
