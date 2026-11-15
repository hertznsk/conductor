"""Temporary TASK21 observation of five nodes during the unchanged full workload."""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import sys
from collections.abc import Generator, Mapping
from functools import wraps
from pathlib import Path
from types import CodeType
from typing import Final

import pytest

_PREFIX: Final = "tests/test_execution/test_local_windows_launch.py::"
TARGETS: Final = frozenset(
    {
        *(
            _PREFIX + f"test_windows_real_claude_sdk_probe_auth_and_main_final_contexts[{ext}]"
            for ext in (".exe", ".cmd", ".bat")
        ),
        *(
            _PREFIX
            + f"test_windows_real_sdk_json_schema_is_preserved_or_refused_without_dropping_flags[{batch}]"
            for batch in ("False", "True")
        ),
    }
)
_OUTPUT: Final = Path(os.environ.get("RUNNER_TEMP", ".")) / "task21-records"

def _context_hash(env: Mapping[str, str]) -> str:
    """Compare only the declared platform/Python/peer identity subset."""
    keys = ("SYSTEMROOT", "COMSPEC", "PYTHONHOME", "PYTHONPATH",
            "WINDOWS_PEER_PYTHON", "WINDOWS_PEER_SCRIPT", "WINDOWS_PEER_RECEIPTS")
    return hashlib.sha256(json.dumps([env.get(key) for key in keys]).encode()).hexdigest()


class Capture:
    """Own only bounded scalar metadata and paths, never processes, transports or frames."""

    def __init__(self, node: str) -> None:
        self.node = node
        self.root: Path | None = None
        self.paths: set[str] = set()
        self.version = False
        self.calls = 0
        self.failures: list[str] = []
        self.context_sha = ""
        self.sdk_lines: dict[int, str] = {}
        self.watch_codes: set[CodeType] = set()

    def note(self, stage: str, **fields: str | int | bool | None) -> None:
        from conductor.execution.local_scope_launcher import _task21_note

        if self.root is not None and not _task21_note(stage, str(self.root), **fields):
            if len(self.failures) < 8:
                self.failures.append("metadata_write_or_cap")

    def raised(self, code: CodeType, offset: int, error: BaseException) -> None:
        """Observe even the exception the original SDK subsequently suppresses."""
        if self.version and code in self.watch_codes:
            self.note(
                "original_exception",
                function=code.co_name,
                offset=offset,
                kind=type(error).__name__,
                errno=error.errno if isinstance(error, OSError) else None,
                winerror=getattr(error, "winerror", None) if isinstance(error, OSError) else None,
            )

    def process_returned(self, code: CodeType, offset: int, process) -> None:
        if self.version:
            if code.co_name == "wait":
                self.note("original_wait_return", exit_code=process)
            else:
                self.note("original_open_return", child_pid=process.pid)

    def sdk_line(self, code: CodeType, line: int) -> None:
        if self.version and line in self.sdk_lines:
            self.note(self.sdk_lines[line])

    def export(self) -> None:
        """Copy only capped metadata outside natural pytest/controller cleanup."""
        destination = _OUTPUT / hashlib.sha256(self.node.encode()).hexdigest()[:16]
        try:
            destination.mkdir(parents=True, exist_ok=True)
            count = total = 0
            if self.root is not None:
                source = self.root / ".task21"
                for path in sorted(source.glob("*.jsonl"))[:16]:
                    data = path.read_bytes()
                    if len(data) > 6144:
                        self.failures.append("oversize_block")
                        data = data[:6144]
                    (destination / path.name).write_bytes(data)
                    total += len(data)
                    count += len(data.splitlines())
                for marker in ("truncated", "io-failed"):
                    if (source / marker).exists():
                        self.failures.append(marker)
            summary = {
                "mode": "TASK21_NATIVE_DIAGNOSTIC_FULL_LOAD_OBSERVE_FIVE",
                "node": self.node,
                "calls": self.calls,
                "events": count,
                "bytes": total,
                "failures": self.failures[:16],
                "cap": {"events": 256, "bytes": 98304},
                "historical_cause_proven": False,
                "missing_child_checkpoint_is_not_a_cause": True,
            }
            (destination / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
        except OSError as error:
            # Diagnostic failure is visible without replacing a test's primary outcome.
            sys.stderr.write(f"TASK21_DIAGNOSTIC_IO_FAILURE {type(error).__name__}\n")


@pytest.hookimpl(wrapper=True)
def pytest_runtest_call(item: pytest.Item) -> Generator[None, None, None]:
    if item.nodeid not in TARGETS:
        return (yield)
    from anyio._core._subprocesses import open_process
    from anyio._backends._asyncio import Process
    from claude_agent_sdk._internal.transport.subprocess_cli import SubprocessCLITransport

    from conductor.execution import local_process_scope as core
    from conductor.execution.types import ProcessLaunchSpec

    capture = Capture(item.nodeid)
    original_check = SubprocessCLITransport._check_claude_version
    original_wrap = core.LocalProcessScopeController.wrap_stdio
    original_close = core.LocalProcessScopeController.close
    original_prepare = core.prepare_windows_launch
    capture.watch_codes = {original_check.__code__, open_process.__code__, Process.wait.__code__}
    tracer = sys.gettrace()
    monitoring = sys.monitoring
    tool_id = next((number for number in (3, 4, 5) if monitoring.get_tool(number) is None), -1)
    installed = False
    code_hash = hashlib.sha256(Path(original_check.__code__.co_filename).read_bytes()).hexdigest()
    source_lines, first_line = inspect.getsourcelines(original_check)
    for offset, text in enumerate(source_lines):
        for fragment, stage in (
            ("stdout_bytes = await", "sdk_receive_begin"),
            ("version_output =", "sdk_receive_returned"),
            ("version_process.terminate()", "sdk_terminate"),
            ("await version_process.wait()", "sdk_wait"),
        ):
            if fragment in text:
                capture.sdk_lines[first_line + offset] = stage

    @wraps(original_wrap)
    async def wrapped(controller, invocation: str, launch: ProcessLaunchSpec) -> ProcessLaunchSpec:
        root = controller.root
        capture.root = root
        (root / ".task21").mkdir(exist_ok=True)
        capture.context_sha = _context_hash(launch.env)
        result = await original_wrap(controller, invocation, launch)
        capture.paths.add(result.argv[0])
        capture.note("registered_launcher", batch=launch.argv[0].lower().endswith((".cmd", ".bat")))
        return result

    @wraps(original_check)
    async def checked(transport) -> None:
        capture.calls += 1
        capture.version = True
        capture.note(
            "original_check_entry",
            calls=capture.calls,
            guard=bool(os.environ.get("CLAUDE_AGENT_SDK_SKIP_VERSION_CHECK")),
            path_matches=transport._cli_path in capture.paths,
            code_sha256=code_hash,
            original_id=id(original_check),
            code_id=id(original_check.__code__),
            inherited_context_matches=_context_hash(os.environ) == capture.context_sha,
        )
        try:
            await original_check(transport)
        finally:
            capture.note("original_check_finally", tracer_preserved=sys.gettrace() is tracer)
            capture.version = False

    @wraps(original_prepare)
    def prepare(launch: ProcessLaunchSpec):
        capture.note(
            "prepare_begin",
            version=launch.argv[-1:] == ("-v",),
            cwd_probe=Path(launch.working_dir).name == "probe",
            peer_script_present="WINDOWS_PEER_SCRIPT" in launch.env,
            systemroot_present="SYSTEMROOT" in launch.env,
            marker_probe=launch.env.get("WINDOWS_PEER_MARKER") == "probe",
            context_matches=_context_hash(launch.env) == capture.context_sha,
        )
        result = original_prepare(launch)
        capture.note("prepare_return", refused=result[1] is not None)
        return result

    @wraps(original_close)
    async def closed(controller):
        try:
            return await original_close(controller)
        finally:
            for proof in controller.proofs:
                capture.note(
                    "original_proof",
                    scope=proof.scope_id,
                    started="COMMAND_STARTED" in proof.events,
                    done=proof.done,
                    empty=proof.kernel_empty,
                    drained=proof.streams_drained,
                    facade_exited=proof.facade_exited,
                    reaped=proof.custodian_reaped,
                )

    try:
        try:
            monitoring.use_tool_id(tool_id, "task21-version")
            installed = True
            monitoring.register_callback(tool_id, monitoring.events.RAISE, capture.raised)
            monitoring.register_callback(tool_id, monitoring.events.EXCEPTION_HANDLED, capture.raised)
            monitoring.register_callback(tool_id, monitoring.events.PY_THROW, capture.raised)
            monitoring.register_callback(tool_id, monitoring.events.PY_RETURN, capture.process_returned)
            monitoring.register_callback(tool_id, monitoring.events.LINE, capture.sdk_line)
            monitoring.set_events(tool_id, monitoring.events.RAISE | monitoring.events.EXCEPTION_HANDLED | monitoring.events.PY_THROW)
            monitoring.set_local_events(tool_id, original_check.__code__, monitoring.events.LINE)
            monitoring.set_local_events(
                tool_id, open_process.__code__, monitoring.events.PY_RETURN
            )
            monitoring.set_local_events(
                tool_id, Process.wait.__code__, monitoring.events.PY_RETURN
            )
        except (ValueError, RuntimeError) as error:
            capture.failures.append("monitoring_" + type(error).__name__)
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(core.LocalProcessScopeController, "wrap_stdio", wrapped)
            patch.setattr(core.LocalProcessScopeController, "close", closed)
            patch.setattr(core, "prepare_windows_launch", prepare)
            patch.setattr(SubprocessCLITransport, "_check_claude_version", checked)
            result = yield
        return result
    finally:
        if installed:
            monitoring.set_events(tool_id, 0)
            monitoring.set_local_events(tool_id, original_check.__code__, 0)
            monitoring.set_local_events(tool_id, open_process.__code__, 0)
            monitoring.set_local_events(tool_id, Process.wait.__code__, 0)
            monitoring.register_callback(tool_id, monitoring.events.RAISE, None)
            monitoring.register_callback(tool_id, monitoring.events.EXCEPTION_HANDLED, None)
            monitoring.register_callback(tool_id, monitoring.events.PY_THROW, None)
            monitoring.register_callback(tool_id, monitoring.events.PY_RETURN, None)
            monitoring.register_callback(tool_id, monitoring.events.LINE, None)
            monitoring.free_tool_id(tool_id)
        capture.note(
            "observation_end",
            one_call=capture.calls == 1,
            method_restored=SubprocessCLITransport._check_claude_version is original_check,
            tracer_preserved=sys.gettrace() is tracer,
        )
        capture.export()
