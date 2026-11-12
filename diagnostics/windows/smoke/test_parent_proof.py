"""Finite native-boundary substitutions; these tests do not prove Windows ABI behavior."""

import time
from dataclasses import dataclass, replace

import psutil
import pytest
from smoke import long_ownership
from smoke.long_diagnostics import OwnershipFailure
from smoke.long_records import Startup
from smoke.parent_ownership_probe import EPOCH, NativeBoundary, NativeChild, install_native
from windows_identity import WindowsIdentity


@dataclass(frozen=True, slots=True)
class Process:
    pid: int
    created: float
    parent: int

    def create_time(self) -> float:
        return self.created

    def ppid(self) -> int:
        return self.parent

    def status(self) -> str:
        return psutil.STATUS_RUNNING


@pytest.fixture
def graph(monkeypatch):
    base = EPOCH + 17_000_000_000_000_000
    births = {100: base, 200: base + 1000, 300: base + 2000}
    processes = {
        pid: Process(pid, float(birth - EPOCH) / 10_000_000, parent)
        for (pid, birth), parent in zip(births.items(), (1, 100, 200), strict=True)
    }
    boundary = NativeBoundary()
    boundary.births = births

    def lookup(pid):
        if pid not in processes:
            raise psutil.NoSuchProcess(pid)
        return processes[pid]

    boundary.lookup = lookup
    install_native(monkeypatch, boundary)
    child = NativeChild()
    owner = long_ownership.CreatorBindings(child, time.monotonic() + 45)
    startup = Startup(300, processes[300].created, f"300:{births[300]}", 200, "gw0")
    return owner, boundary, processes, startup


@pytest.mark.parametrize("edges", [1, 2, 3])
def test_bounded_edges_grant_only_source_and_allow_query_promotion(graph, edges):
    # Requirement: unlabelled bridges retain queries; a later controller must prove its own edge.
    owner, api, processes, startup = graph
    if edges == 1:
        processes[300] = replace(processes[300], parent=100)
        startup = replace(startup, parent=100)
    if edges == 3:
        api.births[400] = api.births[200]
        processes[400] = Process(400, processes[200].created, 200)
        processes[300] = replace(processes[300], parent=400)
        startup = replace(startup, parent=400)
    assert owner.admit(startup, OwnershipFailure("run", "startup-parse")) is None
    assert {n.probe.process.pid for n in owner.nodes.values() if n.kind == "source"} == {300}
    if edges > 1:
        controller = Startup(
            200, processes[200].created, f"200:{api.births[200]}", 100, "controller"
        )
        assert owner.admit(controller, OwnershipFailure("run", "startup-parse")) is None
        assert owner.nodes[controller.identity].kind == "source"
        assert len(api.opened) == edges
    owner.close_probes([n.probe for n in owner.nodes.values()])
    assert len(api.closed) == edges
    assert all(rights == 0x101000 and not inherit for _, rights, inherit in api.opened)
    assert 100 not in api.closed


@pytest.mark.parametrize(
    "damage",
    [
        "birth",
        "parent",
        "key",
        "foreign",
        "cycle",
        "depth",
        "tick",
        "ancestor-gone",
        "candidate-gone",
        "exited",
        "unknown",
        "cap",
        "sealed",
        "deadline",
        "deadline-commit",
        "pid",
    ],
)
def test_refusal_never_promotes_or_leaks_new_queries(graph, monkeypatch, damage):
    # Requirement: every failed fence is terminal and rolls back only this attempt's handles.
    owner, api, processes, startup = graph
    if damage == "birth":
        startup = replace(startup, created=startup.created + 1)
    if damage == "parent":
        startup = replace(startup, parent=99)
    if damage == "key":
        startup = replace(startup, identity=f"300:{api.births[300] + 1}")
    if damage == "foreign":
        processes[200] = replace(processes[200], parent=1)
    if damage == "cycle":
        processes[200] = replace(processes[200], parent=300)
    if damage == "depth":
        for pid, parent in ((200, 400), (400, 500), (500, 100)):
            api.births[pid] = api.births[100]
            processes[pid] = Process(pid, processes[100].created, parent)
    if damage == "tick":
        api.births[200] = api.births[300] + 1
        processes[200] = replace(processes[200], created=processes[300].created)
        assert float(api.births[200]) == float(api.births[300])
    if damage.endswith("-gone"):
        processes.pop(300 if damage == "candidate-gone" else 200)
    if damage in ("exited", "unknown"):
        api.states[200] = 0 if damage == "exited" else 0xFFFFFFFF
    if damage == "cap":
        owner.acquisitions = 5
    if damage == "sealed":
        owner.sealed = True
    if damage == "deadline":
        owner.end = time.monotonic() - 1
    if damage == "deadline-commit":
        waited = api.WaitForSingleObject

        def wait(handle, milliseconds):
            result = waited(handle, milliseconds)
            if len(api.waits) == 6:
                owner.end = time.monotonic() - 1
            return result

        monkeypatch.setattr(api, "WaitForSingleObject", wait)
    if damage == "pid":
        original = api.GetProcessId
        monkeypatch.setattr(api, "GetProcessId", lambda h: original(h) + (h != 100))
    result = owner.admit(startup, OwnershipFailure("run", "startup-parse"))
    assert (result is None) == (damage == "candidate-gone")
    assert list(owner.nodes) == [owner.root.probe.key]
    assert set(api.closed) == set(api.handles)
    if damage == "birth":
        assert not api.opened


@pytest.mark.parametrize("ordinal", [1, 2])
@pytest.mark.parametrize("interrupt", [False, True])
def test_constructor_unwind_owns_raw_handle_and_preserves_primary(
    graph, monkeypatch, ordinal, interrupt
):
    # Requirement: partial OSError/KI closes raw and earlier tentative handles exactly once.
    owner, api, _, startup = graph
    primary = KeyboardInterrupt() if interrupt else PermissionError(13, "private")

    def construct(handle, owned):
        if len(api.opened) == ordinal:
            raise primary
        return WindowsIdentity(handle, owned)

    monkeypatch.setattr(long_ownership, "WindowsIdentity", construct)
    if interrupt:
        with pytest.raises(KeyboardInterrupt) as caught:
            owner.admit(startup, OwnershipFailure("run", "startup-parse"))
        assert caught.value is primary
    else:
        refusal = owner.admit(startup, OwnershipFailure("run", "startup-parse"))
        assert refusal[1].kind == "PermissionError"
    assert len(api.opened) == ordinal
    assert set(api.closed) == set(api.handles)
    assert list(owner.nodes) == [owner.root.probe.key]


def test_query_header_is_validated_and_cached_birth_is_never_replaced(graph):
    # Requirement: an existing query key cannot bypass its own startup birth/key/parent fences.
    owner, api, processes, startup = graph
    assert owner.admit(startup, OwnershipFailure("run", "startup-parse")) is None
    controller = Startup(200, processes[200].created, f"200:{api.births[200]}", 100, "controller")
    result = owner.admit(
        replace(controller, created=controller.created + 1), OwnershipFailure("run", "x")
    )
    assert result[1].stage == "birth-check"
    assert owner.nodes[controller.identity].kind == "query"
    api.births[200] += 1
    result = owner.admit(controller, OwnershipFailure("run", "x"))
    assert result is not None
    assert owner.nodes[controller.identity].kind == "query"
    assert len(api.opened) == 2 and not api.closed
    owner.close_probes([n.probe for n in owner.nodes.values()])


@pytest.mark.parametrize("after_commit", [False, True])
def test_interrupt_at_source_commit_keeps_exact_authority(graph, after_commit):
    # Requirement: interruption after the assignment retains source; before it rolls back.
    owner, api, _, startup = graph
    primary = KeyboardInterrupt()

    class Commit(dict[str, long_ownership.BoundNode]):
        def __setitem__(self, key, value):
            if value.kind == "source":
                if after_commit:
                    super().__setitem__(key, value)
                raise primary
            return super().__setitem__(key, value)

    owner.nodes = Commit(owner.nodes)
    with pytest.raises(KeyboardInterrupt) as caught:
        owner.admit(startup, OwnershipFailure("run", "startup-parse"))
    assert caught.value is primary
    assert (startup.identity in owner.nodes) == after_commit
    assert len(api.closed) == (0 if after_commit else 2)
    owner.close_probes([n.probe for n in owner.nodes.values()])


def test_failed_attempts_exhaust_irrevocable_native_budget(graph):
    # Requirement: four terminal attempts cannot recycle five native acquisitions after rollback.
    owner, api, processes, startup = graph
    processes[200] = replace(processes[200], parent=1)
    results = [owner.admit(startup, OwnershipFailure("run", "x")) for _ in range(4)]
    assert [r[0] for r in results] == [
        "ownership-unavailable",
        "ownership-unavailable",
        "ownership-count-cap",
        "ownership-count-cap",
    ]
    assert owner.attempts == 4 and owner.acquisitions == 5
    assert len(api.opened) == 5 and set(api.closed) == set(api.handles)
    assert list(owner.nodes) == [owner.root.probe.key]


def test_raw_close_failure_never_replaces_constructor_interrupt(graph, monkeypatch):
    # Requirement: checked failed raw close stays visible without replacing the original KI.
    owner, api, _, startup = graph
    primary = KeyboardInterrupt()

    def construct(handle, owned):
        raise primary

    closed = api.CloseHandle

    def failure(handle):
        closed(handle)
        return False

    monkeypatch.setattr(long_ownership, "WindowsIdentity", construct)
    monkeypatch.setattr(api, "CloseHandle", failure)
    with pytest.raises(KeyboardInterrupt) as caught:
        owner.admit(startup, OwnershipFailure("run", "x"))
    assert caught.value is primary
    assert owner.errors == ["cleanup-close-failed"]
    assert len(api.closed) == 1 and len(api.opened) == 1


@pytest.mark.parametrize("primary_before", [False, True])
def test_close_interrupt_preserves_primary_and_closes_remaining_handles(
    graph, monkeypatch, primary_before
):
    # Requirement: one interrupted close cannot skip other retained handles or replace primary.
    owner, api, _, startup = graph
    assert owner.admit(startup, OwnershipFailure("run", "x")) is None
    close = long_ownership.ProcessProbe.close
    primary = KeyboardInterrupt()

    def interrupted(probe):
        close(probe)
        if probe.process.pid == 300:
            raise KeyboardInterrupt()

    monkeypatch.setattr(long_ownership.ProcessProbe, "close", interrupted)
    if primary_before:
        try:
            raise primary
        except KeyboardInterrupt as active:
            owner.finish(time.monotonic() + 3)
            assert active is primary
    else:

        def status_interrupt(handle, milliseconds):
            raise primary

        monkeypatch.setattr(api, "WaitForSingleObject", status_interrupt)
        with pytest.raises(KeyboardInterrupt) as caught:
            owner.finish(time.monotonic() + 3)
        assert caught.value is primary
    assert len(api.closed) == 2 and owner.errors[-1] == "cleanup-close-failed"
    assert len(primary.__notes__) == 1
