"""Bounded publication and exact file export of compact long-control evidence."""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import replace
from itertools import islice
from pathlib import Path

from artifact_policy import MIB, UnsafeArtifact, environment_sanitizer
from artifact_snapshot import bounded_snapshot
from smoke.long_manifest import (
    FILENAME,
    ControlResult,
    Entry,
    Manifest,
    consistent,
    parse_manifest,
    required_issues,
    serialize_manifest,
)
from smoke.long_protocol import CASE_PROCESSES, PROCESS_CAP
from smoke.long_records import ParsedControl, control_records


def publish(source: Path, destination: Path, result: ControlResult) -> bool:
    """Write only validated bounded receipts and the same typed contract used for export."""
    sanitizer = environment_sanitizer()
    destination.mkdir(parents=True)
    draft = Manifest(
        result.workers,
        result.outcome,
        result.cleanup_error is None,
        result.cleanup_error,
        False,
        (),
        (),
    )
    paths = sorted(islice(source.glob("*.jsonl"), CASE_PROCESSES + 1))
    entries: list[Entry] = []
    valid: list[tuple[Path, ParsedControl]] = []
    seen: Counter[str] = Counter()
    issues: set[str] = set()
    if len(paths) > CASE_PROCESSES:
        issues.add("process-count-cap")
    for path in paths[:CASE_PROCESSES]:
        name, role = "unknown-receipt", "unknown"
        try:
            match = FILENAME.fullmatch(path.name)
            if match is None:
                raise UnsafeArtifact("long-filename-refused")
            name, role = path.name, match[2]
            control = control_records(bounded_snapshot(path, PROCESS_CAP), sanitizer)
            if control.startup.pid != int(match[1]) or control.startup.role != role:
                raise UnsafeArtifact("long-producer-mismatch")
            if role not in draft.roles:
                role = "unknown"
                raise UnsafeArtifact("long-role-extra")
            seen[role] += 1
            valid.append((path, control))
        except (UnsafeArtifact, OSError) as error:
            reason = "long-source-unavailable"
            if isinstance(error, UnsafeArtifact):
                reason = (
                    error.reason
                    if error.reason
                    in (
                        "long-filename-refused",
                        "long-producer-mismatch",
                        "long-role-extra",
                    )
                    else "long-source-refused"
                )
            entries.append(Entry(name, role, "withheld", 0, None, reason, False))
            issues.add(reason)
    if any(source.glob("*.failure")):
        issues.add("probe-sink-failed")
    controls: list[ParsedControl] = []
    for path, control in valid:
        role = control.startup.role
        if seen[role] != 1 or len(paths) > CASE_PROCESSES:
            entries.append(
                Entry(path.name, role, "withheld", 0, None, "role-set-incomplete", control.terminal)
            )
            if seen[role] > 1:
                issues.add("role-restarted")
            continue
        (destination / path.name).write_bytes(control.content)
        entries.append(
            Entry(
                path.name,
                role,
                "complete",
                len(control.content),
                hashlib.sha256(control.content).hexdigest(),
                None,
                control.terminal,
            )
        )
        controls.append(control)
    draft = replace(draft, receipts=tuple(entries))
    issues |= required_issues(draft, tuple(controls))
    manifest = replace(draft, issues=tuple(sorted(issues)), complete=not issues)
    payload = serialize_manifest(manifest)
    manifest = parse_manifest(payload)
    consistent(manifest, tuple(controls))
    if len(payload) + sum(e.bytes for e in entries) > MIB // 2:
        raise UnsafeArtifact("long-export-cap")
    sanitizer.published(payload.decode(), PROCESS_CAP)
    (destination / "manifest.json").write_bytes(payload)
    print(
        f"Long control w{result.workers}: evidence="
        f"{'complete' if manifest.complete else 'incomplete'}.",
        flush=True,
    )
    return manifest.complete


def exported_paths(directory: Path) -> list[str]:
    """Reparse actual bytes and corroborate parent outcome with the controller session witness."""
    if directory.is_symlink():
        raise UnsafeArtifact("long-directory-refused")
    sanitizer = environment_sanitizer()
    payload = bounded_snapshot(directory / "manifest.json", PROCESS_CAP)
    manifest = parse_manifest(payload)
    if directory.name != f"long-w{manifest.workers}":
        raise UnsafeArtifact("long-directory-refused")
    sanitizer.published(payload.decode(), PROCESS_CAP)
    paths = [str(directory / "manifest.json")]
    total = len(payload)
    controls: list[ParsedControl] = []
    for entry in manifest.receipts:
        if entry.status == "withheld":
            continue
        control = control_records(bounded_snapshot(directory / entry.path, PROCESS_CAP), sanitizer)
        if (
            len(control.content) != entry.bytes
            or hashlib.sha256(control.content).hexdigest() != entry.sha256
            or control.startup.role != entry.role
            or entry.path != f"{control.startup.pid}-{entry.role}.jsonl"
            or control.terminal is not entry.terminal
        ):
            raise UnsafeArtifact("long-published-mismatch")
        controls.append(control)
        total += len(control.content)
        paths.append(str(directory / entry.path))
    if total > MIB // 2:
        raise UnsafeArtifact("long-export-cap")
    consistent(manifest, tuple(controls))
    return paths
