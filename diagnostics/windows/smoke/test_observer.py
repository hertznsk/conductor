"""Real process controls for inherited output and frozen post-root observation."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import BinaryIO

import psutil
import pytest
from artifact_audit import audit
from artifact_policy import MIB, Record, Sanitizer, environment_sanitizer
from diagnostic_sink import Sink
from support import ProcessProbe, read_records, record_peer_evidence, stop_owned, wait_until

DRIVER = Path(__file__).with_name("driver.py")
SPECIMEN = Path(__file__).with_name("specimen.py")


@pytest.mark.parametrize(
    ("code", "fault"),
    [
        (0, ""),
        (1, ""),
        (7, ""),
        (7, "binding"),
        (7, "nosuch"),
        (7, "denied"),
        (7, "final"),
    ],
)
def test_immediate_exit_preserved_on_binding_fault(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    code: int,
    fault: str,
) -> None:
    # Requirement: a real short-lived child retains its code even when the observer cannot bind.
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    command = tmp_path / "command.json"
    command.write_text(json.dumps([sys.executable, "-c", f"raise SystemExit({code})"]))
    if fault:
        monkeypatch.setenv("SMOKE_BINDING_FAULT", fault)
    result = subprocess.run(
        [sys.executable, str(DRIVER), str(artifacts), str(command)], timeout=10, check=False
    )
    assert result.returncode == code
    records = read_records(artifacts / "supervisor.jsonl")
    assert records[-1]["root_code"] == code
    assert records[-1]["observer_failed"] is bool(fault)
    if fault:
        assert any(record["event"] == "observer.error" for record in records)


@pytest.mark.parametrize("fault", ["binding", "final"])
def test_audit_preserves_root_code_after_observer_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    # Requirement: failed evidence retains the real child outcome through the final manifest.
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    command = tmp_path / "command.json"
    command.write_text(json.dumps([sys.executable, "-c", "raise SystemExit(7)"]))
    monkeypatch.setenv("SMOKE_BINDING_FAULT", fault)
    result = subprocess.run(
        [sys.executable, str(DRIVER), str(artifacts), str(command)], timeout=10, check=False
    )
    assert result.returncode == 7
    records = read_records(artifacts / "supervisor.jsonl")
    assert any(record["event"] == "observer.error" for record in records)
    assert records[-1]["root_code"] == 7 and records[-1]["observer_failed"] is True

    staging = tmp_path / "refused"
    assert audit(artifacts, staging) is False
    manifest = json.loads((staging / "manifest.json").read_text())
    assert manifest["structured_artifacts_complete"] is False
    supervisor = next(item for item in manifest["artifacts"] if item["path"] == "supervisor.jsonl")
    assert supervisor["status"] == "withheld" and supervisor["reason"] == "producer-incomplete"
    assert manifest["root_outcome"]["root_code"] == 7
    assert manifest["root_outcome"]["observer_failed"] is True


@pytest.mark.parametrize("mode", ["natural", "live", "interrupted"])
@pytest.mark.parametrize("topology", ["parent", "chain"])
def test_known_child_outlives_root_without_eof_wait(
    tmp_path: Path, mode: str, topology: str
) -> None:
    # Requirement: prove the bound root's exit even when a known intermediate parent stays live.
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    command = tmp_path / "command.json"
    command.write_text(
        json.dumps([sys.executable, str(SPECIMEN.with_name("peer.py")), str(tmp_path), topology])
    )
    foreign = subprocess.Popen(
        [sys.executable, "-c", "import threading;threading.Event().wait(15)"]
    )
    observer = subprocess.Popen(
        [sys.executable, str(DRIVER), str(artifacts), str(command)],
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
    )
    connection: socket.socket | None = None
    peer: psutil.Process | None = None
    parent: psutil.Process | None = None
    owned: dict[int, psutil.Process] = {}
    probes: dict[int, ProcessProbe] = {}
    ready: list[Record] = []
    try:
        deadline = time.monotonic() + 8
        wait_until(lambda: (tmp_path / "child.ready").exists(), deadline)
        info = json.loads((tmp_path / "child.ready").read_text())
        peer = psutil.Process(info["pid"])
        assert peer.create_time() == info["created"]
        parent_info = json.loads(
            (
                tmp_path / ("intermediate.ready" if topology == "chain" else "parent.ready")
            ).read_text()
        )
        parent = psutil.Process(parent_info["pid"])
        assert parent.create_time() == parent_info["created"]
        owned.update((process.pid, process) for process in (peer, parent))
        for role, process in (("child-ready", peer), ("parent-ready", parent)):
            ready.append(
                {
                    "event": "binding",
                    "role": role,
                    "pid": process.pid,
                    "created": process.create_time(),
                }
            )
        peer_pid = peer.pid
        connection = socket.create_connection(("127.0.0.1", info["port"]), timeout=3)
        wait_until(
            lambda: any(
                record.get("pid") == peer_pid
                for record in read_records(artifacts / "processes.jsonl")
            ),
            deadline,
        )
        before = {
            record["identity"]: record
            for record in read_records(artifacts / "processes.jsonl")
            if record["event"] == "observed"
        }
        binding = next(
            record
            for record in read_records(artifacts / "supervisor.jsonl")
            if record["event"] == "binding"
        )
        for record in before.values():
            pid = record["pid"]
            assert isinstance(pid, int)
            process = psutil.Process(pid)
            owned[process.pid] = process
        for process in (*owned.values(), psutil.Process(observer.pid), psutil.Process(foreign.pid)):
            probes[process.pid] = ProcessProbe.bind(process)
        root_pid = binding["pid"]
        root_key = binding["identity"]
        assert isinstance(root_pid, int) and isinstance(root_key, str)
        assert probes[root_pid].key == root_key
        ready.extend(probe.record("ready") for probe in probes.values())
        (tmp_path / "root.release").touch()
        wait_until(
            lambda: any(
                record["event"] == "root-exit"
                for record in read_records(artifacts / "supervisor.jsonl")
            ),
            deadline,
        )
        wait_until(
            lambda: any(
                record["event"] == "post.begin"
                for record in read_records(artifacts / "post-root.jsonl")
            ),
            deadline,
        )
        if mode == "natural":
            connection.sendall(b"x")
            (tmp_path / "parent.release").touch()
        if mode == "interrupted":
            observer.send_signal(
                signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGTERM
            )
        assert observer.wait(timeout=3) == 7
        post = read_records(artifacts / "post-root.jsonl")
        identities = {
            record["identity"]: record for record in post if record["event"] == "observed"
        }
        child = next(record for record in identities.values() if record["pid"] == peer.pid)
        assert child["identity"] == probes[peer.pid].key
        assert child["status"] == ("proved-exited" if mode == "natural" else "live")
        assert child["parent_identity"] in identities
        root = identities[root_key]
        assert root["status"] == "proved-exited"
        assert post[-1]["root_code"] == 7
        assert post[-1]["interrupted"] is (mode == "interrupted")
        assert post[-1]["complete"] is (mode == "natural")
        assert post[-1]["observation_detached"] is (mode != "natural")
        assert set(identities) == set(before)
        assert post[0]["known"] == len(before)
        child_key = child["identity"]
        assert isinstance(child_key, str)
        ancestry = {child_key}
        cursor = child
        while cursor["identity"] != root_key:
            edge = cursor["parent_identity"]
            assert isinstance(edge, str)
            assert edge in identities and edge not in ancestry
            ancestry.add(edge)
            cursor = identities[edge]
        if topology == "chain":
            assert probes[parent.pid].key in ancestry
            assert probes[parent.pid].record("post-root")["status"] == (
                "proved-exited" if mode == "natural" else "live"
            )
        assert probes[root_pid].record("post-root")["status"] == "proved-exited"
        assert probes[peer.pid].record("post-root")["status"] == (
            "proved-exited" if mode == "natural" else "live"
        )
        if mode == "natural":
            assert all(record["status"] == "proved-exited" for record in identities.values())
            assert all(record["first_exit"] is not None for record in identities.values())
        else:
            assert child["first_exit"] is None and child["last_live"] is not None
        assert all(record["pid"] != foreign.pid for record in identities.values())
        assert foreign.poll() is None
    finally:
        primary_error = sys.exception()
        failures: list[tuple[str, Exception]] = []
        sink: Sink | None = None
        receipt: Path | None = None
        cleanup_records: list[Record] = []
        try:
            destination = Path(os.environ.get("SMOKE_EXPORT_ROOT", str(tmp_path)))
            destination.mkdir(parents=True, exist_ok=True)
            receipt = destination / f"peer-{topology}-{mode}.jsonl"
            sink = Sink(receipt, environment_sanitizer(), MIB)
            record_peer_evidence(sink, artifacts, ready)
            for probe in probes.values():
                sink.emit(probe.record("before-cleanup"))
        except Exception as error:
            # At this test boundary optional evidence errors must not replace its primary outcome.
            failures.append(("export", error))
        finally:
            try:
                try:
                    if connection is not None:
                        # EOF releases this QA-owned peer even after an earlier assertion failed.
                        connection.close()
                    (tmp_path / "parent.release").touch()
                    (tmp_path / "root.release").touch()
                    if observer.poll() is None:
                        try:
                            for process in psutil.Process(observer.pid).children(recursive=True):
                                owned.setdefault(process.pid, process)
                        except psutil.NoSuchProcess:
                            pass
                finally:
                    cleanup_deadline = time.monotonic() + 15
                    stop_owned([observer, foreign], cleanup_deadline, list(owned.values()))
                for probe in probes.values():
                    wait_until(
                        lambda probe=probe: probe.record("cleanup")["status"] == "proved-exited",
                        cleanup_deadline,
                    )
                    cleanup_records.append(probe.record("cleanup"))
            except Exception as error:
                failures.append(("cleanup", error))
            finally:
                try:
                    if sink is not None:
                        try:
                            if not failures:
                                for record in cleanup_records:
                                    sink.emit(record)
                                sink.emit(
                                    {"event": "exit", "scope": "qa-cleanup", "complete": True}
                                )
                        finally:
                            sink.close()
                        assert sink.failure is None, "Peer evidence export was incomplete."
                        assert receipt is not None
                        receipt.with_suffix(".sha256").write_text(
                            hashlib.sha256(receipt.read_bytes()).hexdigest() + "\n",
                            encoding="ascii",
                        )
                except Exception as error:
                    failures.append(("export", error))
                finally:
                    for probe in probes.values():
                        try:
                            probe.close()
                        except Exception as error:
                            failures.append(("handle cleanup", error))
        if failures:
            if primary_error is not None:
                for phase, error in failures:
                    primary_error.add_note(f"Peer {phase} failed ({type(error).__name__}).")
            elif len(failures) == 1:
                raise failures[0][1]
            else:
                raise ExceptionGroup("Peer finalization failed", [error for _, error in failures])


@pytest.mark.parametrize("failure", ["setup", "record", "sink"])
@pytest.mark.parametrize("primary", [False, True], ids=["clean-body", "primary-error"])
def test_peer_export_failure_closes_owned_resources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str, primary: bool
) -> None:
    # Requirement: export faults preserve the primary outcome and close real QA processes/handles.
    scenario = tmp_path / "scenario"
    scenario.mkdir()
    monkeypatch.setenv("SMOKE_EXPORT_ROOT", str(scenario / "published"))
    descriptor_path = tmp_path / "owned-query-resource"
    descriptor_path.write_bytes(b"")
    probes: list[ProcessProbe] = []
    streams: list[BinaryIO] = []
    descriptors: list[int] = []
    connections: list[socket.socket] = []
    closing_states: list[Record] = []
    bind = ProcessProbe.bind
    close = ProcessProbe.close
    record = ProcessProbe.record
    connect = socket.create_connection
    sink_type = Sink
    primary_error = AssertionError("injected-primary-outcome")

    def tracked_bind(process: psutil.Process) -> ProcessProbe:
        probe = bind(process)
        probes.append(probe)
        stream = descriptor_path.open("rb")
        streams.append(stream)
        descriptors.append(stream.fileno())
        return probe

    def tracked_close(probe: ProcessProbe) -> None:
        closing_states.append(record(probe, "before-probe-close"))
        try:
            close(probe)
        finally:
            streams[probes.index(probe)].close()

    def tracked_record(probe: ProcessProbe, stage: str) -> Record:
        result = record(probe, stage)
        if primary and stage == "post-root":
            raise primary_error
        return result

    def tracked_connect(address: tuple[str, int], timeout: float) -> socket.socket:
        connection = connect(address, timeout=timeout)
        connections.append(connection)
        return connection

    def refuse_setup() -> None:
        raise OSError("injected-peer-export")

    def refuse_records(sink: Sink, artifacts: Path, ready: list[Record]) -> None:
        raise OSError("injected-peer-export")

    def tracked_sink(path: Path, sanitizer: Sanitizer, cap: int) -> Sink:
        sink = sink_type(path, sanitizer, cap)
        assert sink.fd is not None
        descriptors.append(sink.fd)

        def refuse_emit(value: Record) -> bool:
            sink.fail("injected-peer-export")
            return False

        if failure == "sink":
            monkeypatch.setattr(sink, "emit", refuse_emit)
        return sink

    monkeypatch.setattr(ProcessProbe, "bind", staticmethod(tracked_bind))
    monkeypatch.setattr(ProcessProbe, "close", tracked_close)
    monkeypatch.setattr(ProcessProbe, "record", tracked_record)
    monkeypatch.setattr(socket, "create_connection", tracked_connect)
    module = sys.modules[__name__]
    monkeypatch.setattr(module, "Sink", tracked_sink)
    if failure == "setup":
        monkeypatch.setattr(module, "environment_sanitizer", refuse_setup)
    elif failure == "record":
        monkeypatch.setattr(module, "record_peer_evidence", refuse_records)
    caught: Exception | None = None
    try:
        try:
            test_known_child_outlives_root_without_eof_wait(scenario, "live", "chain")
        except (OSError, AssertionError) as error:
            caught = error
        open_descriptors = []
        for descriptor in descriptors:
            try:
                os.fstat(descriptor)
                open_descriptors.append(descriptor)
            except OSError as error:
                assert error.errno == errno.EBADF
        native_closed = [probe.native.closed for probe in probes if probe.native is not None]
        snapshot = {
            "pids": [probe.process.pid for probe in probes],
            "states_at_close": closing_states,
            "open_descriptors": open_descriptors,
            "open_sockets": [
                connection.fileno() for connection in connections if connection.fileno() >= 0
            ],
            "native_closed": native_closed,
            "primary_preserved": caught is primary_error,
            "notes": getattr(caught, "__notes__", []),
        }
        (tmp_path / "fault-check.json").write_text(json.dumps(snapshot))
        assert probes and len(closing_states) == len(probes), snapshot
        assert not open_descriptors and not snapshot["open_sockets"], snapshot
        assert all(native_closed), snapshot
        assert all(item["status"] == "proved-exited" for item in closing_states), snapshot
        if sys.platform != "win32":
            wait_until(
                lambda: all(not psutil.pid_exists(probe.process.pid) for probe in probes),
                time.monotonic() + 3,
            )
        if primary:
            assert caught is primary_error
            assert any("Peer export" in note for note in getattr(caught, "__notes__", []))
        else:
            assert isinstance(caught, (OSError, AssertionError))
    finally:
        # Rescue a genuine RED without hiding its pre-rescue process/descriptor observations.
        for connection in connections:
            connection.close()
        (scenario / "parent.release").touch()
        (scenario / "root.release").touch()
        stop_owned([], time.monotonic() + 15, [probe.process for probe in probes])
        for probe in probes:
            if probe.native is not None and not probe.native.closed:
                close(probe)
        for stream in streams:
            stream.close()


def test_peer_export_uses_finite_fields_and_sanitizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Requirement: peer export excludes raw payloads and sanitizes even allowed identity fields.
    secret = "qa-only-peer-canary-629"
    monkeypatch.setenv("PEER_CANARY", secret)
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "supervisor.jsonl").write_text(
        json.dumps(
            {
                "event": "binding",
                "monotonic": 1.0,
                "identity": secret,
                "pid": 7,
                "argv": [secret],
                "environ": {"PRIVATE": secret},
                "unexpected": secret,
            }
        )
        + "\n"
    )
    path = tmp_path / "peer.jsonl"
    sink = Sink(path, environment_sanitizer(), MIB)
    try:
        record_peer_evidence(sink, artifacts, [])
    finally:
        sink.close()
    assert sink.failure is None
    records = read_records(path)
    assert len(records) == 1
    assert records[0]["identity"] == "[redacted]"
    assert records[0]["pid"] == 7 and records[0]["observed_at"] == 1.0
    assert secret not in path.read_text()
    assert not {"argv", "environ", "unexpected"}.intersection(records[0])


def test_watchdog_survives_unconfigure_and_closed_stderr(tmp_path: Path) -> None:
    # Requirement: the actual 60-second watchdog writes into the private fd after pytest cleanup.
    program = (
        "import os,sys,threading,pytest;"
        "code=pytest.main(['-p','no:cacheprovider','-p','pr629_diag',"
        "'-o','faulthandler_timeout=0',sys.argv[1]]);"
        "os.close(2);threading.Event().wait(62);sys.exit(code)"
    )
    environment = {**os.environ, "PR629_DIAG_DIR": str(tmp_path), "DIAG_SMOKE_FAIL": "0"}
    result = subprocess.run(
        [sys.executable, "-c", program, str(SPECIMEN)], env=environment, timeout=75, check=False
    )
    assert result.returncode == 0
    stack = next((tmp_path / "private").glob("*.stack.txt")).read_text()
    assert "Timeout (0:01:00)!" in stack and "threading.py" in stack
    assert any(
        record["event"] == "unconfigure.end"
        for record in read_records(next(tmp_path.glob("*.phase.jsonl")))
    )


@pytest.mark.parametrize("failure", ["setup", "rearm"])
def test_plugin_failure_does_not_change_pytest_result(tmp_path: Path, failure: str) -> None:
    # Requirement: sink and watchdog failures do not change a passing pytest outcome.
    directory = tmp_path / "records"
    if failure == "setup":
        directory.write_text("not a directory")
    else:
        directory.mkdir()
    program = (
        "import faulthandler,pytest,sys;"
        + (
            "faulthandler.dump_traceback_later=lambda *a,**k:(_ for _ in ()).throw(OSError());"
            if failure == "rearm"
            else ""
        )
        + "sys.exit(pytest.main(['-p','no:cacheprovider','-p','pr629_diag',sys.argv[1]]))"
    )
    result = subprocess.run(
        [sys.executable, "-c", program, str(SPECIMEN)],
        env={**os.environ, "PR629_DIAG_DIR": str(directory)},
        timeout=10,
        check=False,
    )
    assert result.returncode == 0


@pytest.mark.parametrize("recipient", ["root", "observer"])
def test_real_signal_keeps_root_outcome_distinct(tmp_path: Path, recipient: str) -> None:
    # Requirement: cancellation is observed separately from a known physical child return code.
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    command = tmp_path / "command.json"
    program = "import signal,threading,pathlib,sys;"
    if sys.platform == "win32":
        program += "signal.signal(signal.SIGBREAK,signal.SIG_IGN);"
    program += "pathlib.Path(sys.argv[1]).touch();threading.Event().wait(15)"
    ready = tmp_path / "signal.ready"
    command.write_text(json.dumps([sys.executable, "-c", program, str(ready)]))
    observer = subprocess.Popen(
        [sys.executable, str(DRIVER), str(artifacts), str(command)],
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
    )
    root: psutil.Process | None = None
    try:
        wait_until(
            lambda: any(
                record["event"] == "binding"
                for record in read_records(artifacts / "supervisor.jsonl")
            ),
            time.monotonic() + 5,
        )
        record = next(
            record
            for record in read_records(artifacts / "supervisor.jsonl")
            if record["event"] == "binding"
        )
        root_pid = record["pid"]
        assert isinstance(root_pid, int)
        root = psutil.Process(root_pid)
        wait_until(ready.exists, time.monotonic() + 5)
        if recipient == "root":
            root.terminate()
        else:
            observer.send_signal(
                signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGTERM
            )
        observer.wait(timeout=5)
        result = read_records(artifacts / "supervisor.jsonl")[-1]
        if recipient == "root":
            assert result["root_code"] is not None and result["root_code"] != 0
        else:
            assert result["root_code"] is None and result["interrupted"] is True
    finally:
        stop_owned([observer], time.monotonic() + 15, [] if root is None else [root])
