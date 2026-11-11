"""Bounded whole-artifact snapshots. Private fault-handler bytes are never uploaded raw."""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from artifact_policy import (
    LOG_CAP,
    RECORD_CAP,
    SCHEMA,
    Record,
    Sanitizer,
    UnsafeArtifact,
)


@dataclass(slots=True)
class Parsed:
    """Accumulate only the small audit summary, not every hot phase event."""

    first: Record = field(default_factory=dict)
    last: Record = field(default_factory=dict)
    events: set[str] = field(default_factory=set)
    kept: list[Record] = field(default_factory=list)
    collected: int = 0
    calls: int = 0
    sequence: int = 0
    physical: dict[str, Record] = field(default_factory=dict)
    finished: set[int] = field(default_factory=set)
    collection: dict[int, str] = field(default_factory=dict)
    identities: set[str] = field(default_factory=set)
    observations: dict[str, Record] = field(default_factory=dict)
    close_errors: list[Record] = field(default_factory=list)
    max_gap: float = 0
    producer_incomplete: bool = False


def test_identity(record: Record, collection: dict[int, str]) -> None:
    """Parse identity against the accumulated parameter-free ordered collection."""
    event = record.get("event")
    if record.get("event") == "expected" and record.get("policy") != SCHEMA:
        raise UnsafeArtifact("unsupported-policy")
    if "nodeid" in record:
        raise UnsafeArtifact("raw-test-identity")
    if (
        "item_index" in record
        or "label" in record
        or event
        in (
            "collected",
            "report",
            "setup.begin",
            "setup.end",
            "call.begin",
            "call.end",
            "teardown.begin",
            "teardown.end",
            "runtest.begin",
            "runtest.end",
        )
    ):
        index, label = record.get("item_index"), record.get("label")
        if type(index) is not int or not isinstance(index, int) or not 0 <= index < 65536:
            raise UnsafeArtifact("invalid-item-index")
        if (
            not isinstance(label, str)
            or not label
            or len(label.encode()) > 256
            or "[" in label
            or "]" in label
        ):
            raise UnsafeArtifact("invalid-item-label")
        if event == "collected":
            if index != len(collection):
                raise UnsafeArtifact("invalid-collection-index")
            collection[index] = label
        elif collection.get(index) != label:
            raise UnsafeArtifact("item-collection-mismatch")
    if event == "report":
        duration = record.get("duration")
        if (
            type(duration) not in (int, float)
            or not isinstance(duration, (int, float))
            or duration < 0
            or record.get("phase") not in ("setup", "call", "teardown")
            or record.get("outcome") not in ("passed", "failed", "skipped")
        ):
            raise UnsafeArtifact("invalid-report")


def bounded_snapshot(path: Path, cap: int) -> bytes:
    if path.is_symlink():
        raise UnsafeArtifact("symlink-source")
    before = path.stat()
    with path.open("rb") as stream:
        content = stream.read(cap + 1)
    after = path.stat()
    if len(content) > cap:
        raise UnsafeArtifact("oversize")
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise UnsafeArtifact("racing-snapshot")
    return content


def records(content: bytes, sanitizer: Sanitizer) -> tuple[bytes, Parsed]:
    if content and not content.endswith(b"\n"):
        raise UnsafeArtifact("partial-jsonl-tail")
    summary = Parsed()
    output = bytearray()
    for line in content.splitlines():
        if len(line) > RECORD_CAP:
            raise UnsafeArtifact("record-oversize")
        try:
            raw = json.loads(line)
        except (ValueError, UnicodeError, RecursionError):
            raise UnsafeArtifact("invalid-json") from None
        if not isinstance(raw, dict):
            raise UnsafeArtifact("invalid-jsonl-record")
        clean = sanitizer.record(raw)
        test_identity(clean, summary.collection)
        if clean.get("sequence") != summary.sequence:
            raise UnsafeArtifact("sequence-gap")
        timestamp = clean.get("monotonic")
        previous = summary.last.get("monotonic", timestamp)
        if not isinstance(timestamp, (int, float)) or not isinstance(previous, (int, float)):
            raise UnsafeArtifact("missing-timestamp")
        if timestamp < previous:
            raise UnsafeArtifact("timestamp-order")
        summary.max_gap = max(summary.max_gap, timestamp - previous)
        event = clean["event"]
        if not isinstance(event, str):
            raise UnsafeArtifact("invalid-event")
        summary.sequence += 1
        summary.first = summary.first or clean
        summary.last = clean
        summary.events.add(event)
        summary.collected += event == "collected"
        summary.calls += event == "report" and clean.get("phase") == "call"
        if event == "report" and clean.get("phase") == "teardown":
            index = clean.get("item_index")
            if (
                type(index) is not int
                or index not in summary.collection
                or index in summary.finished
            ):
                raise UnsafeArtifact("invalid-terminal-node")
            summary.finished.add(index)
        identity, role = clean.get("identity"), clean.get("role")
        if event == "observed" and isinstance(identity, str) and isinstance(role, str):
            summary.identities.add(identity)
            if len(summary.observations) >= 65536 and identity not in summary.observations:
                raise UnsafeArtifact("identity-budget")
            summary.observations[identity] = clean
            if role == "controller" or role.startswith("gw"):
                if len(summary.physical) >= 256 and identity not in summary.physical:
                    raise UnsafeArtifact("role-budget")
                summary.physical[identity] = clean
        if event == "process.close_error":
            if len(summary.close_errors) >= 256:
                raise UnsafeArtifact("close-error-budget")
            summary.close_errors.append(clean)
        if event in (
            "configured",
            "expected",
            "launch",
            "exit",
            "post.end",
            "binding",
            "environment",
            "version",
            "service-file",
            "root-exit",
            "step",
        ):
            summary.kept.append(clean)
        if event in ("diagnostic.failure", "observer.error") or clean.get("omitted"):
            # A valid error record does not invalidate a later, known root outcome.
            summary.producer_incomplete = True
        output.extend((json.dumps(clean) + "\n").encode())
    return bytes(output), summary


@dataclass(frozen=True, slots=True)
class Prefix:
    """A validated sequential prefix, never a repaired complete raw artifact."""

    content: bytes = b""
    source_bytes: int = 0
    validated_bytes: int = 0
    records_consumed: int = 0
    first_monotonic: float | None = None
    last_monotonic: float | None = None
    terminal_event_seen: bool = False
    discarded_tail_bytes: int = 0
    gap_count: int = 0
    error_counts: dict[str, int] = field(default_factory=dict)
    right_censored: bool = True
    measurement_status: str = "unavailable"
    sha256: str = hashlib.sha256(b"").hexdigest()

    def records(self, sanitizer: Sanitizer) -> Iterator[Record]:
        for line in self.content.splitlines():
            yield sanitizer.record(json.loads(line))


def prefix_records(path: Path, sanitizer: Sanitizer) -> Prefix:
    """Read once; reject a racing source and stop at the first invalid whole record."""
    source_bytes = 0
    try:
        if path.is_symlink():
            raise UnsafeArtifact("symlink-source")
        before = path.stat()
        source_bytes = before.st_size
        with path.open("rb") as stream:
            content = stream.read(LOG_CAP)
        after = path.stat()
        if (
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
            before.st_dev,
            before.st_ino,
        ) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_dev, after.st_ino):
            raise UnsafeArtifact("racing-snapshot")
    except (OSError, UnsafeArtifact) as error:
        reason = error.reason if isinstance(error, UnsafeArtifact) else "source-unavailable"
        return Prefix(
            source_bytes=source_bytes, discarded_tail_bytes=source_bytes, error_counts={reason: 1}
        )
    offset = count = gaps = 0
    first: float | None = None
    last: float | None = None
    terminal = False
    errors: dict[str, int] = {}
    collection: dict[int, str] = {}
    for line in content.splitlines(keepends=True):
        try:
            if not line.endswith(b"\n"):
                raise UnsafeArtifact("partial-jsonl-tail")
            if len(line) > RECORD_CAP:
                raise UnsafeArtifact("record-oversize")
            raw = json.loads(line)
            if not isinstance(raw, dict):
                raise UnsafeArtifact("invalid-jsonl-record")
            record = sanitizer.record(raw)
            test_identity(record, collection)
            if record.get("sequence") != count:
                gaps += 1
                raise UnsafeArtifact("sequence-gap")
            stamp = record.get("monotonic")
            if type(stamp) not in (int, float):
                raise UnsafeArtifact("missing-timestamp")
            if not isinstance(stamp, (int, float)):
                raise UnsafeArtifact("missing-timestamp")
            if last is not None and stamp < last:
                gaps += 1
                raise UnsafeArtifact("timestamp-order")
        except (ValueError, UnicodeError, RecursionError, UnsafeArtifact) as error:
            reason = error.reason if isinstance(error, UnsafeArtifact) else "invalid-json"
            errors[reason] = errors.get(reason, 0) + 1
            break
        offset += len(line)
        count += 1
        first = stamp if first is None else first
        last = float(stamp)
        terminal = record["event"] in ("exit", "post.end", "unconfigure.end")
        if record["event"] in ("observer.error", "diagnostic.failure") or record.get("omitted"):
            reason = str(record.get("reason", "producer-incomplete"))
            code = reason if reason in errors or len(errors) < 127 else "other-errors"
            errors[code] = errors.get(code, 0) + 1
    if source_bytes > LOG_CAP:
        errors["input-cap"] = 1
    used = content[:offset]
    censored = bool(errors) or offset != source_bytes or not terminal
    return Prefix(
        used,
        source_bytes,
        offset,
        count,
        first,
        last,
        terminal,
        source_bytes - offset,
        gaps,
        errors,
        censored,
        "limited" if censored and count else "measured" if count else "unavailable",
        hashlib.sha256(used).hexdigest(),
    )


def stack_snapshot(content: bytes, sanitizer: Sanitizer) -> bytes:
    text = content.decode("utf-8")
    sanitizer.cutoff(text)
    for line in text.splitlines():
        if line and not re.fullmatch(
            r"Timeout \(.*\)!|(?:Current thread|Thread) .+|"
            r'  File ".+", line \d+, in .+|  <no Python frame>|  \.\.\.|'
            r"Extension modules: .+",
            line,
        ):
            raise UnsafeArtifact("unsupported-stack-format")
    return sanitizer.text(text, 16 * 1024 * 1024).encode()


def coverage_snapshot(content: bytes, sanitizer: Sanitizer) -> bytes:
    if b"<!DOCTYPE" in content or b"<!ENTITY" in content:
        raise UnsafeArtifact("unsupported-xml")
    root = ET.fromstring(content)
    if root.tag != "coverage":
        raise UnsafeArtifact("invalid-coverage-root")
    for element in root.iter():
        for key, value in tuple(element.attrib.items()):
            element.set(key, sanitizer.text(value))
        if element.text:
            element.text = sanitizer.text(element.text)
        if element.tail:
            element.tail = sanitizer.text(element.tail)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)
