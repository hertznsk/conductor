"""Strict compact receipt parsing, including the local numeric session witness."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass

from artifact_policy import Sanitizer, UnsafeArtifact
from artifact_snapshot import records
from smoke.long_protocol import (
    EXCEPTIONS,
    FAILURES,
    FIELDS,
    FILES,
    FUNCTIONS,
    KINDS,
    NAMES,
    PROCESS_CAP,
    STAGES,
    STATUSES,
)


@dataclass(frozen=True, slots=True)
class Startup:
    pid: int
    created: float
    identity: str
    parent: int
    role: str


@dataclass(frozen=True, slots=True)
class ParsedControl:
    content: bytes
    startup: Startup
    terminal: bool
    session_exitcode: int | None


def control_records(content: bytes, sanitizer: Sanitizer) -> ParsedControl:
    """Independently parse the finite sidecar protocol before any publication or ownership claim."""
    cleaned, parsed = records(content, sanitizer)
    first = parsed.first
    if (first.get("event"), first.get("kind"), first.get("stage")) != (
        "observed",
        "process",
        "startup",
    ):
        raise UnsafeArtifact("long-startup-missing")
    pid, created, identity = (first.get(k) for k in ("pid", "created", "identity"))
    if (
        type(pid) is not int
        or not isinstance(created, (int, float))
        or not isinstance(identity, str)
    ):
        raise UnsafeArtifact("long-identity-invalid")
    if not identity.startswith(f"{pid}:") or len(identity) > 80:
        raise UnsafeArtifact("long-identity-invalid")
    session_exitcode: int | None = None
    terminal_seen = False
    exceptions = 0
    frames: Counter[int] = Counter()
    for line in cleaned.splitlines():
        r = json.loads(line)
        if set(r) - FIELDS or r.get("event") not in ("observed", "scope", "worker-down"):
            raise UnsafeArtifact("long-field-refused")
        if any(
            r.get(k) != first.get(k)
            for k in ("pid", "parent", "created", "identity", "role", "worker")
        ):
            raise UnsafeArtifact("long-identity-changed")
        if (
            r.get("scope") != "long-control"
            or r.get("kind") not in KINDS
            or r.get("stage") not in STAGES
        ):
            raise UnsafeArtifact("long-code-refused")
        for key, allowed in (
            ("name", NAMES),
            ("path", FILES | {"unknown"}),
            ("exception_type", EXCEPTIONS),
            ("error", FAILURES),
            ("status", STATUSES),
            ("phase", {"setup", "call", "teardown", "collection", "internal"}),
            ("outcome", {"passed", "failed", "skipped"}),
        ):
            if r.get(key) is not None and r[key] not in allowed:
                raise UnsafeArtifact("long-code-refused")
        if "exitcode" in r:
            code = r["exitcode"]
            shape = (r.get("event"), r.get("kind"), r.get("stage"))
            if (
                shape != ("observed", "process", "sessionfinish.end")
                or type(code) is not int
                or not -2147483648 <= code <= 4294967295
                or session_exitcode is not None
                or r["sequence"] == 0
                or terminal_seen
                or set(r)
                != {
                    "sequence",
                    "monotonic",
                    "utc",
                    "event",
                    "pid",
                    "parent",
                    "created",
                    "identity",
                    "worker",
                    "role",
                    "scope",
                    "kind",
                    "stage",
                    "exitcode",
                }
            ):
                raise UnsafeArtifact("long-exit-witness-refused")
            session_exitcode = code
        elif r.get("kind") == "process" and r.get("stage") != "startup":
            raise UnsafeArtifact("long-exit-witness-refused")
        terminal_seen |= r.get("stage") == "unconfigure.end"
        if r["kind"] == "exception":
            exceptions += 1
            if exceptions > 8 or r.get("known") != exceptions:
                raise UnsafeArtifact("long-exception-cap")
        if r["kind"] == "frame":
            number = r.get("known")
            if type(number) is not int or not 1 <= number <= exceptions:
                raise UnsafeArtifact("long-frame-refused")
            frames[number] += 1
            if frames[number] > 8:
                raise UnsafeArtifact("long-frame-cap")
            if r.get("status") == "known":
                if (
                    r.get("path") not in FILES
                    or r.get("name") not in FUNCTIONS
                    or type(r.get("ident")) is not int
                    or r["ident"] <= 0
                ):
                    raise UnsafeArtifact("long-frame-refused")
            elif (r.get("status"), r.get("path"), r.get("name"), r.get("ident")) != (
                "unknown",
                "unknown",
                "unknown",
                None,
            ):
                raise UnsafeArtifact("long-frame-refused")
    if len(cleaned) > PROCESS_CAP:
        raise UnsafeArtifact("long-process-cap")
    sanitizer.published(cleaned.decode(), PROCESS_CAP)
    parent, role = first.get("parent"), first.get("role")
    if type(parent) is not int or not isinstance(role, str) or first.get("worker") != role:
        raise UnsafeArtifact("long-identity-invalid")
    return ParsedControl(
        cleaned,
        Startup(pid, float(created), identity, parent, role),
        parsed.last.get("stage") == "unconfigure.end",
        session_exitcode,
    )
