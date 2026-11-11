"""Single-writer whole records. Diagnostic failures never escape into pytest hooks."""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from artifact_policy import LOG_CAP, RECORD_CAP, Record, Sanitizer, UnsafeArtifact


class Sink:
    """Own one fd, sequence and failure latch; partial tails are never continued."""

    def __init__(self, path: Path, sanitizer: Sanitizer, cap: int = LOG_CAP) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.sanitizer = sanitizer
        self.fd: int | None = None
        self.failure: str | None = None
        self.sequence = 0
        self.bytes = 0
        self.cap = cap
        self.fallback_attempted = False
        try:
            binary = os.O_BINARY if sys.platform == "win32" else 0
            self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | binary, 0o600)
        except OSError:
            self.fail("open-failed")

    def fail(self, reason: str) -> None:
        self.failure = self.failure or reason
        if self.fallback_attempted:
            return
        self.fallback_attempted = True
        try:
            # A separate fixed-size latch also covers a policy cap with healthy disk.
            with self.path.with_suffix(".failure").open("w", encoding="ascii") as stream:
                stream.write("diagnostic-incomplete\n")
        except OSError:
            self.failure = self.failure or "failure-latch-unavailable"
        try:
            if sys.__stderr__ is not None:
                os.write(sys.__stderr__.fileno(), b"Diagnostic evidence is incomplete.\n")
        except (OSError, ValueError, AttributeError):
            return

    def emit(self, record: Record) -> bool:
        if not self._lock.acquire(timeout=0.1):
            self.fail("writer-lock-budget")
            return False
        try:
            if self.failure is not None or self.fd is None:
                return False
            try:
                clean = self.sanitizer.record(
                    {
                        "sequence": self.sequence,
                        "monotonic": time.monotonic(),
                        "utc": datetime.now(UTC).isoformat(),
                        **record,
                    }
                )
                payload = (json.dumps(clean) + "\n").encode("utf-8")
                if len(payload) > RECORD_CAP or self.bytes + len(payload) > self.cap:
                    self.fail("size-budget")
                    return False
                deadline = time.monotonic() + 0.1
                offset = 0
                interruptions = 0
                while offset < len(payload):
                    if time.monotonic() >= deadline:
                        self.fail("write-budget")
                        return False
                    try:
                        written = os.write(self.fd, payload[offset:])
                    except InterruptedError:
                        interruptions += 1
                        if interruptions >= 8:
                            self.fail("interrupted-write-budget")
                            return False
                        continue
                    if written == 0:
                        self.fail("zero-write")
                        return False
                    offset += written
                    self.bytes += written
                self.sequence += 1
                return True
            except (OSError, ValueError, TypeError, UnicodeError, UnsafeArtifact):
                self.fail("record-refused")
                return False
        finally:
            self._lock.release()

    def close(self) -> None:
        if self.fd is not None:
            fd, self.fd = self.fd, None
            try:
                os.close(fd)
            except OSError:
                self.fail("close-failed")
