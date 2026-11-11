"""Bounded whole-artifact snapshots. Private fault-handler bytes are never uploaded raw."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from artifact_policy import RECORD_CAP, Record, Sanitizer, UnsafeArtifact


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
    finished: set[str] = field(default_factory=set)
    identities: set[str] = field(default_factory=set)
    max_gap: float = 0
    producer_incomplete: bool = False


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
            nodeid = clean.get("nodeid")
            if not isinstance(nodeid, str) or nodeid in summary.finished:
                raise UnsafeArtifact("invalid-terminal-node")
            summary.finished.add(nodeid)
        identity, role = clean.get("identity"), clean.get("role")
        if event == "observed" and isinstance(identity, str) and isinstance(role, str):
            summary.identities.add(identity)
            if role == "controller" or role.startswith("gw"):
                if len(summary.physical) >= 256 and identity not in summary.physical:
                    raise UnsafeArtifact("role-budget")
                summary.physical[identity] = clean
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
