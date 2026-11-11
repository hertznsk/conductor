"""R3 structured-artifact policy. Actions output is deliberately outside this policy."""

from __future__ import annotations

import json
import math
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from record_schema import BOOL_FIELDS, EVENTS, INTEGER_FIELDS, NUMBER_FIELDS, STRING_FIELDS

MIB: Final = 1024 * 1024
RECORD_CAP: Final = 64 * 1024
FIELD_CAP: Final = 4096
LOG_CAP: Final = 64 * MIB
STACK_CAP: Final = 16 * MIB
COVERAGE_CAP: Final = 32 * MIB
BUNDLE_CAP: Final = 512 * MIB
LEVEL: Final = "PRELIMINARY_PYTHON_OS"
SCHEMA: Final = "windows-preflight-r3"
MANDATORY_RECORDS: Final[tuple[str, ...]] = (
    "environment.jsonl",
    "supervisor.jsonl",
    "processes.jsonl",
    "post-root.jsonl",
    "step.jsonl",
)
type Value = str | int | float | bool | None | list[str] | list[int]
type Record = dict[str, Value]

LIST_FIELDS: Final = frozenset(("argv", "cov_source", "expected_files", "affinity", "thread_ids"))


@dataclass(slots=True)
class UnsafeArtifact(Exception):
    """A typed refusal; Python context managers must be able to update its traceback."""

    reason: str

    def __str__(self) -> str:
        return self.reason


class Sanitizer:
    """A bounded in-memory set of exact values, never serialized or hashed."""

    def __init__(self, environment: Mapping[str, str]) -> None:
        values = {
            value
            for name, value in environment.items()
            if value and re.search(r"(?:^|_)(?:TOKEN|PASSWORD|SECRET|API_KEY|CANARY)$", name, re.I)
        }
        if len(values) > 128 or sum(len(value) for value in values) > MIB:
            raise UnsafeArtifact("secret-policy-budget")
        variants: set[str] = set()
        for value in values:
            lf = value.replace("\r\n", "\n")
            for normalized in (value, lf, lf.replace("\n", "\r\n")):
                variants.add(normalized)
                variants.add(json.dumps(normalized, ensure_ascii=True)[1:-1])
                variants.add(json.dumps(normalized, ensure_ascii=False)[1:-1])
        self.variants: tuple[str, ...] = tuple(
            sorted(variants, key=lambda value: len(value), reverse=True)
        )

    def text(self, value: str, cap: int = FIELD_CAP) -> str:
        if len(value.encode("utf-8")) > cap:
            raise UnsafeArtifact("field-oversize")
        if "\x00" in value or re.search(
            r"(?i:os\.environ|environ\s*\(\s*\{)|"
            r"['\"](?:PATH|Path|HOME|USERPROFILE|PYTHONPATH)['\"]\s*:\s*['\"]",
            value,
        ):
            raise UnsafeArtifact("unsupported-field")
        result = value
        for secret in self.variants:
            result = result.replace(secret, "[redacted]")
        result = re.sub(
            r"(?i)((?:authorization|password|api[_-]?key|token|secret)\s*[:=]\s*"
            r"(?:bearer\s+)?)(?!\[redacted\])[^\s,;'\"}]+",
            r"\1[redacted]",
            result,
        )
        result = re.sub(r"(https?://)[^/\s:@]+:[^/\s@]+@", r"\1[redacted]@", result)
        if any(secret in result for secret in self.variants):
            raise UnsafeArtifact("secret-remains")
        if len(result.encode("utf-8")) > cap:
            raise UnsafeArtifact("sanitized-oversize")
        return result

    def cutoff(self, value: str) -> None:
        """A live text snapshot must not publish an unresolved credential prefix."""
        if value and not value.endswith("\n"):
            raise UnsafeArtifact("partial-text-snapshot")
        for secret in self.variants:
            for size in range(1, min(len(secret), len(value) + 1)):
                if value.endswith(secret[:size]):
                    raise UnsafeArtifact("ambiguous-secret-cutoff")

    def published(self, value: str, cap: int) -> None:
        if self.text(value, cap) != value:
            raise UnsafeArtifact("final-scan-refused")

    def record(self, raw: Record) -> Record:
        event = raw.get("event")
        if not isinstance(event, str) or event not in EVENTS:
            raise UnsafeArtifact("unknown-event")
        result: Record = {}
        for key, value in raw.items():
            if (
                key
                not in STRING_FIELDS | INTEGER_FIELDS | NUMBER_FIELDS | BOOL_FIELDS | LIST_FIELDS
            ):
                raise UnsafeArtifact("unknown-field")
            if value is None:
                result[key] = None
                continue
            match value:
                case str() if key in STRING_FIELDS:
                    if key in ("reason", "error") and not re.fullmatch(
                        r"[A-Za-z0-9_-]{1,80}", value
                    ):
                        raise UnsafeArtifact("invalid-diagnostic-code")
                    result[key] = self.text(value)
                case bool() if key in BOOL_FIELDS:
                    result[key] = value
                case int() if type(value) is int and key in INTEGER_FIELDS | NUMBER_FIELDS:
                    result[key] = value
                case float() if key in NUMBER_FIELDS and math.isfinite(value):
                    result[key] = value
                case list() if key in LIST_FIELDS and len(value) <= 256:
                    if key in ("affinity", "thread_ids"):
                        numbers = [item for item in value if isinstance(item, int)]
                        if len(numbers) != len(value):
                            raise UnsafeArtifact("invalid-numeric-list")
                        result[key] = numbers
                    else:
                        strings = [item for item in value if isinstance(item, str)]
                        if len(strings) != len(value):
                            raise UnsafeArtifact("invalid-string-list")
                        result[key] = [self.text(item) for item in strings]
                case _:
                    # The boundary must reject untrusted JSON variants, including non-finite floats.
                    raise UnsafeArtifact("invalid-field-type")
        return result


def environment_sanitizer() -> Sanitizer:
    return Sanitizer(os.environ)
