"""Finite in-process exception note projection; no IO, paths or traceback rendering."""

from __future__ import annotations

import builtins
import json
from dataclasses import dataclass, replace
from typing import Literal, Self, assert_never

import psutil
from artifact_policy import CLOSE_TYPES, Record, Sanitizer, UnsafeArtifact
from smoke.long_export import CheckedControl
from smoke.long_manifest import (
    ERRORS,
    ISSUES,
    REASONS,
    ControlResult,
    Normal,
    Timeout,
    Unknown,
)
from smoke.long_protocol import CASE_PROCESSES, EXCEPTIONS, FAILURES, FILES, FUNCTIONS, ROLES

OWNER_REASONS = frozenset(
    (
        "long-startup-missing",
        "partial-jsonl-tail",
        "invalid-json",
        "sequence-gap",
        "long-identity-invalid",
        "ownership-mismatch",
    )
)
OWNER_TYPES = tuple(getattr(builtins, name) for name in CLOSE_TYPES) + (
    psutil.Error,
    psutil.AccessDenied,
    UnsafeArtifact,
)


@dataclass(frozen=True, slots=True)
class OwnershipFailure:
    scan: str
    stage: str
    role: str = "unknown"
    first_line_bytes: int | None = None
    line_complete: bool | None = None
    native_bound: bool | None = None
    kind: str = "unknown"
    errno: int | None = None
    winerror: int | None = None
    reason: str = "none"
    additional: int = 0

    def caused_by(self, error: OSError | psutil.Error | UnsafeArtifact) -> OwnershipFailure:
        kind = type(error).__name__ if type(error) in OWNER_TYPES else "unknown"
        errno, winerror = None, None
        if type(error) in OWNER_TYPES and isinstance(error, OSError):
            errno, winerror = error.errno, getattr(error, "winerror", None)
        reason = "other-unsafe" if isinstance(error, UnsafeArtifact) else "none"
        if (
            type(error) is UnsafeArtifact
            and isinstance(error.reason, str)
            and error.reason in OWNER_REASONS
        ):
            reason = error.reason
        return replace(
            self,
            kind=kind,
            reason=reason,
            errno=errno if type(errno) is int else None,
            winerror=winerror if type(winerror) is int else None,
        )

    def summary(self) -> str:
        scan = self.scan if self.scan in ("run", "final") else "unknown"
        stages = (
            "open",
            "read",
            "startup-parse",
            "process-lookup",
            "birth-query",
            "birth-check",
            "parent-query",
            "parent-check",
            "bind",
            "key-check",
            "candidate-close",
        )
        stage = self.stage if self.stage in stages else "unknown"
        role = self.role if self.role in ROLES else "unknown"
        kind = self.kind if self.kind in tuple(t.__name__ for t in OWNER_TYPES) else "unknown"
        reason = (
            self.reason
            if self.reason in OWNER_REASONS | {"none", "other-unsafe"}
            else "other-unsafe"
        )
        complete = (
            str(self.line_complete).lower() if type(self.line_complete) is bool else "unknown"
        )
        native = str(self.native_bound).lower() if type(self.native_bound) is bool else "unknown"
        more = (
            number(self.additional)
            if type(self.additional) is int and 0 <= self.additional <= CASE_PROCESSES
            else "unknown"
        )
        return (
            f" owner={scan}:{stage}:{role}:{kind}:{number(self.errno)}:{number(self.winerror)}"
            f":{reason}:{number(self.first_line_bytes)}:{complete}:{native}:more={more}"
        )


def worker_details(rows: list[Record], ordinal: int | None) -> str:
    frames = [
        r
        for r in rows
        if r.get("kind") == "frame" and type(r.get("known")) is int and r["known"] == ordinal
    ]
    known = []
    inner = "unknown"
    for frame in frames:
        path, name, line = frame.get("path"), frame.get("name"), frame.get("ident")
        valid = path in FILES and name in FUNCTIONS and type(line) is int and 0 < line <= 2147483647
        inner = "true" if valid else "false" if frame.get("status") == "unknown" else "unknown"
        if valid:
            known.append(f"{path}:{name}:{line}")
    service, isolated = "unknown", "unknown"
    for row in rows:
        if row.get("kind") == "configuration" and row.get("name") == "service-conftest":
            service = row["status"] if row.get("status") in ("present", "absent") else "unknown"
        if row.get("kind") == "configuration" and row.get("name") == "isolated_paths-all":
            isolated = (
                str(row["complete"]).lower() if type(row.get("complete")) is bool else "unknown"
            )
    return (
        f"setup={service}:{isolated} frames#{number(ordinal)}="
        f"{'>'.join(known[-2:]) or 'unknown'} inner-known={inner}"
    )


class SafeControlNote(str):
    def __new__(cls) -> Self:
        raise UnsafeArtifact("safe-note-renderer-owned")


def control_note(error: BaseException | None) -> SafeControlNote | None:
    """Recognize only the local marker, never a prefix or arbitrary exception text."""
    return next((n for n in getattr(error, "__notes__", ()) if type(n) is SafeControlNote), None)


def transfer_note(primary: BaseException | None, secondary: BaseException) -> None:
    note = control_note(primary)
    if note is not None:
        secondary.add_note(note)


def number(value: str | int | float | bool | None | list[str] | list[int]) -> str:
    if type(value) is not int:
        return "unknown"
    return str(value) if -2147483648 <= value <= 18446744073709551615 else "unknown"


def render_note(
    result: ControlResult,
    checked: CheckedControl | None,
    category: Literal["checked", "summary-unavailable", "publication-refused"],
    *,
    ownership: OwnershipFailure | None = None,
) -> SafeControlNote:
    """Create a bounded ASCII line only from actual parent state and strict compact receipts."""
    if category not in ("checked", "summary-unavailable", "publication-refused"):
        raise UnsafeArtifact("safe-summary-category")
    match result.outcome:
        case Normal(code):
            outcome = "normal:" + number(code)
        case Timeout():
            outcome = "timeout:null"
        case Unknown():
            outcome = "unknown:null"
        case unreachable:
            assert_never(unreachable)
    cleanup = result.cleanup_error if result.cleanup_error in ERRORS else "unknown"
    if result.cleanup_error is None:
        cleanup = "none"
    mandatory = (
        f"PR629_CONTROL workers={number(result.workers)} outcome={outcome}"
        f" cleanup={'true' if result.cleanup_error is None else 'false'}"
        f" error={cleanup}"
    )
    if ownership is not None:
        mandatory += ownership.summary()
    if checked is None:
        status = (
            "publication-refused" if category == "publication-refused" else "summary-unavailable"
        )
        text = mandatory + f" evidence=unknown summary={status} details=omitted"
    else:
        manifest = checked.manifest
        issues = ",".join(i if i in ISSUES else "unknown" for i in manifest.issues) or "none"
        mandatory += f" evidence={'complete' if manifest.complete else 'partial'} issues={issues}"
        roles = []
        details = []
        for role in manifest.roles:
            entry = next((e for e in manifest.receipts if e.role == role), None)
            status = "missing"
            if entry is not None:
                status = {"complete": "published", "withheld": "withheld"}[entry.status]
            reason = entry.reason if entry is not None and entry.reason in REASONS else "none"
            terminal = "unknown" if entry is None else "true" if entry.terminal else "false"
            roles.append(f"{role}={status}:{terminal}:{reason}")
            control = next((c for c in checked.controls if c.startup.role == role), None)
            sink: Record = {}
            exception: Record = {}
            errors = 0
            rows = []
            if control is not None:
                for line in control.content.splitlines():
                    record: Record = json.loads(line)
                    rows.append(record)
                    if record.get("kind") == "main-sink":
                        sink = record
                    if record.get("kind") == "exception":
                        errors += 1
                        exception = exception or record
            failure = sink.get("error")
            failure = (
                failure
                if isinstance(failure, str) and failure in FAILURES
                else "none"
                if sink and failure is None
                else "unknown"
            )
            kind, phase = exception.get("exception_type"), exception.get("phase")
            kind = kind if isinstance(kind, str) and kind in EXCEPTIONS else "unknown"
            phase = (
                phase
                if phase in ("setup", "call", "teardown", "collection", "internal")
                else "unknown"
            )
            details.append(
                f"{role}.sink={failure}:{number(sink.get('expected'))}:{number(sink.get('bytes'))}"
                f" exception={kind}:{phase}:{number(exception.get('errno'))}"
                f":{number(exception.get('winerror'))}"
                f" more={'omitted' if errors > 1 else 'none'}"
            )
            if role in ("gw0", "gw1"):
                ordinal = exception.get("known")
                details.append(
                    f"{role}." + worker_details(rows, ordinal if type(ordinal) is int else None)
                )
        controller = next((c for c in checked.controls if c.startup.role == "controller"), None)
        witness = controller.session_exitcode if controller is not None else None
        binding = "unknown"
        match result.outcome:
            case Normal(code):
                binding = (
                    "missing" if witness is None else "matched" if witness == code else "mismatch"
                )
            case Timeout() | Unknown():
                pass
            case unreachable:
                assert_never(unreachable)
        mandatory += " " + " ".join(roles) + f" controller={number(witness)}:{binding}"
        text = mandatory + " " + " ".join(details)
        if len(text.encode("ascii")) > 2048:
            text = mandatory + " details=omitted"
    Sanitizer({}).published(text, 2048)
    return str.__new__(SafeControlNote, text)
