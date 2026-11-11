"""Closed metadata boundary and the single completeness rule for compact receipts."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from typing import Final, assert_never

from artifact_policy import UnsafeArtifact
from smoke.long_protocol import CASE_PROCESSES, PROCESS_CAP
from smoke.long_records import ParsedControl

type JSONValue = str | int | float | bool | None | list[JSONValue] | dict[str, JSONValue]
type JSONObject = dict[str, JSONValue]
ERRORS: Final = frozenset(
    (
        "ownership-count-cap",
        "ownership-unavailable",
        "ownership-mismatch",
        "cleanup-unconfirmed",
        "cleanup-unavailable",
        "cleanup-close-failed",
    )
)
REASONS: Final = frozenset(
    (
        "long-filename-refused",
        "long-producer-mismatch",
        "long-role-extra",
        "long-source-refused",
        "long-source-unavailable",
        "role-set-incomplete",
    )
)
ISSUES: Final = REASONS | frozenset(
    (
        "process-count-cap",
        "role-restarted",
        "role-missing",
        "probe-sink-failed",
        "nonterminal-receipt",
        "cleanup-incomplete",
        "control-timeout",
        "root-outcome-unavailable",
        "controller-exit-missing",
        "controller-exit-mismatch",
    )
)
FILENAME: Final = re.compile(r"(\d{1,10})-(controller|gw0|gw1|unknown)\.jsonl")


@dataclass(frozen=True, slots=True)
class Normal:
    code: int

    def __post_init__(self) -> None:
        if type(self.code) is not int or not -2147483648 <= self.code <= 4294967295:
            raise UnsafeArtifact("long-outcome-refused")


@dataclass(frozen=True, slots=True)
class Timeout:
    """The original deadline expired before a normal wait result."""


@dataclass(frozen=True, slots=True)
class Unknown:
    """No authoritative normal result was obtained before cleanup."""


type Outcome = Normal | Timeout | Unknown


@dataclass(frozen=True, slots=True)
class ControlResult:
    workers: int
    outcome: Outcome
    cleanup_error: str | None = None


@dataclass(frozen=True, slots=True)
class Entry:
    path: str
    role: str
    status: str
    bytes: int
    sha256: str | None
    reason: str | None
    terminal: bool


@dataclass(frozen=True, slots=True)
class Manifest:
    workers: int
    outcome: Outcome
    cleanup_complete: bool
    error: str | None
    complete: bool
    issues: tuple[str, ...]
    receipts: tuple[Entry, ...]

    @property
    def roles(self) -> tuple[str, ...]:
        return ("controller", "gw0", "gw1") if self.workers == 2 else ("controller", "gw0")


def unique_pairs(pairs: list[tuple[str, JSONValue]]) -> JSONObject:
    result: JSONObject = {}
    for key, value in pairs:
        if key in result:
            raise UnsafeArtifact("long-duplicate-key")
        result[key] = value
    return result


def fields(value: JSONValue, keys: str) -> JSONObject:
    if not isinstance(value, dict) or set(value) != set(keys.split()):
        raise UnsafeArtifact("long-metadata-fields")
    return value


def parse_manifest(payload: bytes) -> Manifest:
    """Parse all metadata, including withheld entries, without coercion or partial exceptions."""
    if len(payload) > PROCESS_CAP:
        raise UnsafeArtifact("long-metadata-cap")
    try:
        raw: JSONValue = json.loads(payload, object_pairs_hook=unique_pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise UnsafeArtifact("long-metadata-json") from None
    data = fields(
        raw,
        "kind workers root_code timeout cleanup_complete error complete "
        "expected_roles issues receipts",
    )
    workers, code = data["workers"], data["root_code"]
    if data["kind"] != "long-control" or type(workers) is not int or workers not in (1, 2):
        raise UnsafeArtifact("long-metadata-refused")
    timeout, cleanup, complete = data["timeout"], data["cleanup_complete"], data["complete"]
    if type(timeout) is not bool or type(cleanup) is not bool or type(complete) is not bool:
        raise UnsafeArtifact("long-metadata-bool")
    outcome: Outcome
    if code is not None:
        if type(code) is not int or data["timeout"] is not False:
            raise UnsafeArtifact("long-outcome-refused")
        outcome = Normal(code)
    else:
        outcome = Timeout() if timeout else Unknown()
    roles = ("controller", "gw0", "gw1") if workers == 2 else ("controller", "gw0")
    error, issues, receipts = data["error"], data["issues"], data["receipts"]
    if error is not None and (not isinstance(error, str) or error not in ERRORS):
        raise UnsafeArtifact("long-error-refused")
    if not isinstance(issues, list) or data["expected_roles"] != list(roles):
        raise UnsafeArtifact("long-issues-refused")
    parsed_issues: list[str] = []
    for issue in issues:
        if not isinstance(issue, str) or issue not in ISSUES:
            raise UnsafeArtifact("long-issues-refused")
        parsed_issues.append(issue)
    if parsed_issues != sorted(set(parsed_issues)):
        raise UnsafeArtifact("long-issues-refused")
    if not isinstance(receipts, list) or len(receipts) > CASE_PROCESSES:
        raise UnsafeArtifact("long-entry-count")
    entries = []
    complete_roles: set[str] = set()
    names: set[str] = set()
    for raw_entry in receipts:
        entry = fields(raw_entry, "path role status bytes sha256 reason terminal")
        name, role, status = entry["path"], entry["role"], entry["status"]
        size, digest, reason, terminal = (
            entry["bytes"],
            entry["sha256"],
            entry["reason"],
            entry["terminal"],
        )
        if (
            not isinstance(name, str)
            or not isinstance(role, str)
            or not isinstance(status, str)
            or role not in (*roles, "unknown")
            or type(size) is not int
            or type(terminal) is not bool
            or status not in ("complete", "withheld")
        ):
            raise UnsafeArtifact("long-entry-refused")
        if digest is not None and not isinstance(digest, str):
            raise UnsafeArtifact("long-entry-refused")
        if reason is not None and (not isinstance(reason, str) or reason not in REASONS):
            raise UnsafeArtifact("long-entry-refused")
        match = FILENAME.fullmatch(name)
        if status == "complete":
            if (
                match is None
                or match[2] != role
                or role not in roles
                or role in complete_roles
                or name in names
                or not 0 < size <= PROCESS_CAP
                or digest is None
                or re.fullmatch("[0-9a-f]{64}", digest) is None
                or reason is not None
            ):
                raise UnsafeArtifact("long-entry-refused")
            complete_roles.add(role)
        elif (
            size != 0
            or digest is not None
            or reason is None
            or (name != "unknown-receipt" and match is None)
        ):
            raise UnsafeArtifact("long-entry-refused")
        names.add(name)
        entries.append(Entry(name, role, status, size, digest, reason, terminal))
    return Manifest(
        workers, outcome, cleanup, error, complete, tuple(parsed_issues), tuple(entries)
    )


def required_issues(manifest: Manifest, controls: tuple[ParsedControl, ...]) -> set[str]:
    """Derive observable incompleteness identically for publication and re-export."""
    issues = {e.reason for e in manifest.receipts if e.reason is not None}
    published = {e.role for e in manifest.receipts if e.status == "complete"}
    if published != set(manifest.roles):
        issues.add("role-missing")
    if any(not c.terminal for c in controls):
        issues.add("nonterminal-receipt")
    if not manifest.cleanup_complete or manifest.error is not None:
        issues.add("cleanup-incomplete")
    witness = next((c.session_exitcode for c in controls if c.startup.role == "controller"), None)
    match manifest.outcome:
        case Normal(code):
            if witness is None:
                issues.add("controller-exit-missing")
            elif code != witness:
                issues.add("controller-exit-mismatch")
        case Timeout():
            issues.add("control-timeout")
        case Unknown():
            issues.add("root-outcome-unavailable")
        case unreachable:
            assert_never(unreachable)
    return issues


def consistent(manifest: Manifest, controls: tuple[ParsedControl, ...]) -> None:
    required = required_issues(manifest, controls)
    if not required <= set(manifest.issues) or manifest.complete != (not manifest.issues):
        raise UnsafeArtifact("long-completeness-refused")


def serialize_manifest(manifest: Manifest) -> bytes:
    code: int | None = None
    timeout = False
    match manifest.outcome:
        case Normal(value):
            code = value
        case Timeout():
            timeout = True
        case Unknown():
            pass
        case unreachable:
            assert_never(unreachable)
    return json.dumps(
        {
            "kind": "long-control",
            "workers": manifest.workers,
            "root_code": code,
            "timeout": timeout,
            "cleanup_complete": manifest.cleanup_complete,
            "error": manifest.error,
            "complete": manifest.complete,
            "expected_roles": manifest.roles,
            "issues": manifest.issues,
            "receipts": [asdict(e) for e in manifest.receipts],
        },
        sort_keys=True,
        indent=2,
    ).encode()
