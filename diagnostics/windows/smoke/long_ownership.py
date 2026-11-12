"""Bound one early creator path; query retention never grants signal authority."""

from __future__ import annotations

import ctypes
import subprocess
import sys
import time
from dataclasses import dataclass, replace
from typing import Literal

import psutil
from artifact_policy import UnsafeArtifact
from process_identity import Identity
from smoke.long_diagnostics import OwnershipFailure
from smoke.long_records import Startup
from smoke.support import ProcessProbe
from windows_identity import WindowsIdentity, kernel_api


@dataclass(frozen=True, slots=True)
class BoundNode:
    probe: ProcessProbe
    parent: int
    kind: Literal["root", "query", "source"]


class CreatorBindings:
    """Accumulate bounded retained identities and irrevocable source admissions."""

    def __init__(self, child: subprocess.Popen[bytes], end: float) -> None:
        self.child, self.end = child, end
        self.sealed = False
        self.attempts = self.acquisitions = 0
        self.errors: list[str] = []
        self.pending: list[ProcessProbe] = []
        self.nodes: dict[str, BoundNode] = {}
        identity = Identity.child(child)
        created = identity.created
        if identity.native is not None:
            created = float(identity.native.ticks - 116444736000000000) / 10_000_000
        probe = ProcessProbe(psutil.Process(child.pid), created, identity.native)
        self.root = BoundNode(probe, probe.process.ppid(), "root")
        self.nodes[probe.key] = self.root

    def early(self) -> None:
        if self.sealed or time.monotonic() >= self.end or self.child.returncode is not None:
            raise UnsafeArtifact("startup-not-bound-before-stop")

    def acquire(self, process: psutil.Process, created: float) -> ProcessProbe:
        """Own raw native acquisition through construction, including interrupted unwind."""
        if len(self.nodes) + len(self.pending) >= 6 or self.acquisitions >= 5:
            raise UnsafeArtifact("ownership-count-cap")
        self.acquisitions += 1
        if sys.platform != "win32":
            probe = ProcessProbe(process, created, None)
            self.pending.append(probe)
            return probe
        api = kernel_api()
        handle = api.OpenProcess(0x101000, False, process.pid)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        native = None
        try:
            native = WindowsIdentity(handle, owned=True)
            probe = ProcessProbe(process, created, native)
            self.pending.append(probe)
            return probe
        finally:
            if not any(p.native is native for p in self.pending):
                primary = sys.exception()
                try:
                    if not api.CloseHandle(handle):
                        self.errors.append("cleanup-close-failed")
                except (OSError, KeyboardInterrupt):
                    self.errors.append("cleanup-close-failed")
                    if primary is None:
                        raise
                    primary.add_note("Secondary failure during partial native close.")

    def close_probes(self, probes: list[ProcessProbe]) -> None:
        primary, deferred = sys.exception(), None
        for probe in probes:
            try:
                probe.close()
            except OSError:
                self.errors.append("cleanup-close-failed")
            except KeyboardInterrupt as error:
                self.errors.append("cleanup-close-failed")
                if primary is not None:
                    primary.add_note("Secondary KeyboardInterrupt during ownership close.")
                elif deferred is None:
                    deferred = error
        if deferred is not None:
            raise deferred

    def fresh(self, node: BoundNode, descendant: BoundNode | None = None) -> None:
        process, probe = psutil.Process(node.probe.process.pid), node.probe
        if process.create_time() != probe.created or process.ppid() != node.parent:
            raise UnsafeArtifact("ownership-mismatch")
        if probe.native is not None:
            seconds = float(probe.native.ticks - 116444736000000000) / 10_000_000
            if seconds != probe.created:
                raise UnsafeArtifact("ownership-mismatch")
        elif sys.platform == "win32":
            raise UnsafeArtifact("ownership-mismatch")
        if probe.record("early")["status"] != "live":
            raise UnsafeArtifact("ownership-mismatch")
        if descendant is not None:
            child = descendant.probe
            child_birth = child.native.ticks if child.native else child.created
            parent_birth = probe.native.ticks if probe.native else probe.created
            if descendant.parent != probe.process.pid or child_birth < parent_birth:
                raise UnsafeArtifact("ownership-mismatch")

    def admit(
        self, first: Startup, context: OwnershipFailure
    ) -> tuple[str, OwnershipFailure] | None:
        """One attempt, two bounded passes; promotion is the final authority commit."""
        stage, native_bound, observing = "process-lookup", None, first.pid
        candidate: BoundNode | None = None
        self.pending = []
        try:
            self.early()
            self.attempts += 1
            if self.attempts > 4:
                raise UnsafeArtifact("ownership-count-cap")
            process = psutil.Process(first.pid)
            stage = "birth-query"
            created = process.create_time()
            stage = "birth-check"
            if created != first.created:
                raise UnsafeArtifact("ownership-mismatch")
            stage = "parent-query"
            parent = process.ppid()
            stage = "parent-check"
            if parent != first.parent:
                raise UnsafeArtifact("ownership-mismatch")
            if first.pid == self.child.pid and (
                first.role != "controller" or first.identity != self.root.probe.key
            ):
                raise UnsafeArtifact("ownership-mismatch")
            if first.role == "controller" and first.pid != self.child.pid:
                if parent != self.child.pid:
                    raise UnsafeArtifact("ownership-mismatch")
            if sys.platform != "win32" and first.pid != self.child.pid:
                if parent != self.child.pid:
                    raise UnsafeArtifact("ownership-mismatch")
            stage = "bind"
            self.early()
            existing = next(
                (n for n in self.nodes.values() if n.probe.process.pid == first.pid), None
            )
            probe = existing.probe if existing else self.acquire(process, created)
            native_bound = probe.native is not None
            stage = "key-check"
            if probe.key != first.identity:
                if probe in self.pending:
                    self.pending.remove(probe)
                    stage = "candidate-close"
                    try:
                        probe.close()
                    except (OSError, KeyboardInterrupt):
                        self.errors.append("cleanup-close-failed")
                        raise
                stage = "key-check"
                raise UnsafeArtifact("ownership-mismatch")
            if existing and (existing.parent != parent or probe.created != created):
                raise UnsafeArtifact("ownership-mismatch")
            candidate = BoundNode(probe, parent, "query")
            chain = [candidate]
            limit = 3 if sys.platform == "win32" and first.role != "controller" else 1
            for _ in range(limit + 1):
                node = chain[-1]
                observing = node.probe.process.pid
                stage = "parent-check"
                self.fresh(node, chain[-2] if len(chain) > 1 else None)
                if node.probe.key == self.root.probe.key:
                    break
                if len(chain) > limit or node.parent == self.root.parent:
                    raise UnsafeArtifact("ownership-mismatch")
                if any(n.probe.process.pid == node.parent for n in chain):
                    raise UnsafeArtifact("ownership-mismatch")
                observing = node.parent
                stage = "process-lookup"
                retained = next(
                    (n for n in self.nodes.values() if n.probe.process.pid == observing), None
                )
                if retained is None:
                    ancestor = psutil.Process(observing)
                    stage = "birth-query"
                    birth = ancestor.create_time()
                    stage = "parent-query"
                    creator = ancestor.ppid()
                    stage = "bind"
                    retained = BoundNode(self.acquire(ancestor, birth), creator, "query")
                chain.append(retained)
            for index, node in enumerate(chain):
                observing = node.probe.process.pid
                stage = "parent-check"
                self.fresh(node, chain[index - 1] if index else None)
            self.early()
            for node in chain:
                self.nodes.setdefault(node.probe.key, node)
            if probe.key != self.root.probe.key:
                self.nodes[probe.key] = replace(candidate, kind="source")
        except psutil.NoSuchProcess as error:
            if observing != first.pid:
                return "ownership-unavailable", replace(
                    context, stage=stage, native_bound=native_bound
                ).caused_by(error)
        except (OSError, psutil.Error, UnsafeArtifact) as error:
            code = (
                "ownership-count-cap"
                if isinstance(error, UnsafeArtifact) and error.reason == "ownership-count-cap"
                else "ownership-unavailable"
            )
            return code, replace(context, stage=stage, native_bound=native_bound).caused_by(error)
        finally:
            committed = self.nodes.get(first.identity)
            if committed is None or committed.kind == "query":
                for probe in self.pending:
                    self.nodes.pop(probe.key, None)
                self.close_probes(self.pending)
            self.pending = []
        return None

    def finish(self, deadline: float) -> None:
        """Observe retained objects after stop, then close every owned query binding."""
        primary, deferred = sys.exception(), None
        try:
            for node in self.nodes.values():
                probe = node.probe
                try:
                    if node.kind == "query" and probe.native is not None:
                        milliseconds = max(0, int((deadline - time.monotonic()) * 1000))
                        probe.native.kernel.WaitForSingleObject(probe.native.handle, milliseconds)
                    if probe.record("cleanup")["status"] != "proved-exited":
                        self.errors.append("cleanup-unconfirmed")
                except (OSError, psutil.Error):
                    self.errors.append("cleanup-unavailable")
                except KeyboardInterrupt as error:
                    self.errors.append("cleanup-unavailable")
                    if primary is not None:
                        primary.add_note("Secondary KeyboardInterrupt during ownership status.")
                    elif deferred is None:
                        deferred = error
        finally:
            try:
                self.close_probes([node.probe for node in self.nodes.values()])
            except KeyboardInterrupt:
                if deferred is None:
                    raise
                deferred.add_note("Secondary KeyboardInterrupt during ownership close.")
        if deferred is not None:
            raise deferred
