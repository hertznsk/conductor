"""Finite in-process exception note projection; no IO, paths or traceback rendering."""

from __future__ import annotations

import json
from typing import Literal, Self, assert_never

from artifact_policy import Record, Sanitizer, UnsafeArtifact
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
from smoke.long_protocol import EXCEPTIONS, FAILURES


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
    return (
        str(value)
        if type(value) is int and -2147483648 <= value <= 18446744073709551615
        else "unknown"
    )


def render_note(
    result: ControlResult,
    checked: CheckedControl | None,
    category: Literal["checked", "summary-unavailable", "publication-refused"],
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
    cleanup = (
        result.cleanup_error
        if result.cleanup_error in ERRORS
        else "none"
        if result.cleanup_error is None
        else "unknown"
    )
    mandatory = (
        f"PR629_CONTROL workers={number(result.workers)} outcome={outcome}"
        f" cleanup={'true' if result.cleanup_error is None else 'false'}"
        f" error={cleanup}"
    )
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
            status = (
                "missing"
                if entry is None
                else "published"
                if entry.status == "complete"
                else "withheld"
            )
            reason = entry.reason if entry is not None and entry.reason in REASONS else "none"
            terminal = "unknown" if entry is None else "true" if entry.terminal else "false"
            roles.append(f"{role}={status}:{terminal}:{reason}")
            control = next((c for c in checked.controls if c.startup.role == role), None)
            sink: Record = {}
            exception: Record = {}
            errors = 0
            if control is not None:
                for line in control.content.splitlines():
                    record: Record = json.loads(line)
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
