"""Contract tests for the ``conductor.execution`` package.

Each test pins one requirement of the runner-backend contract: immutability,
field defaults, protocol shape, leaf purity, literal vocabularies, and the
exact ``StartError`` fill-in/reconstruction rule the executor relies on for
``__cause__`` parity.
"""

from __future__ import annotations

import dataclasses
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Literal, get_args

import pytest

from conductor.execution import (
    CommandOutcome,
    CommandResult,
    CommandSpec,
    RunnerBackend,
    RunnerCapabilities,
    RunOutcome,
    RunSpec,
    StartError,
    StartErrorKind,
    WorkspaceLease,
)


def _fill_start_error(e: OSError) -> StartError:
    """Fill ``StartError`` from an exception exactly as the plan specifies."""
    return StartError(
        kind="file_not_found" if isinstance(e, FileNotFoundError) else "os_error",
        message=e.strerror if getattr(e, "errno", None) is not None else str(e),
        errno=e.errno,
        filename=e.filename,
    )


def _reconstruct_cause(start_error: StartError) -> OSError:
    """Reconstruct the original exception exactly as the plan specifies."""
    cause_type = FileNotFoundError if start_error.kind == "file_not_found" else OSError
    if start_error.errno is not None:
        return cause_type(start_error.errno, start_error.message, start_error.filename)
    return cause_type(start_error.message)


class TestFrozenContract:
    """Requirement: every contract type is a frozen (immutable) dataclass."""

    @pytest.mark.parametrize(
        "instance",
        [
            CommandSpec(command="echo", args=("hello",)),
            CommandResult(outcome="completed"),
            StartError(kind="file_not_found", message="missing"),
            WorkspaceLease(lease_id="r1", backend="local", incarnation="i1"),
            RunSpec(run_id="r1"),
            RunnerCapabilities(batch=True, sessions=False, shared_workspace=True, snapshots=False),
        ],
    )
    def test_assignment_raises_frozen_instance_error(self, instance: Any) -> None:
        # Requirement: contract immutability — no caller may mutate a shared
        # contract value after the backend handed it out. Frozen dataclasses
        # reject any attribute assignment, so "outcome" works for every type.
        with pytest.raises(dataclasses.FrozenInstanceError):
            instance.outcome = "timed_out"


class TestDefaults:
    """Requirement: field defaults match the contract spec exactly."""

    def test_command_spec_defaults(self) -> None:
        # Requirement: a bare rendered command carries no args, inherits the
        # working dir and control environment, and sends no stdin/timeout.
        spec = CommandSpec(command="echo")
        assert spec.args == ()
        assert spec.working_dir is None
        assert spec.env == {}
        assert spec.inherit_control_environment is True
        assert spec.stdin is None
        assert spec.timeout is None

    def test_command_result_defaults(self) -> None:
        # Requirement: an outcome-only result implies empty output, no exit
        # code, no resolved command, no start error, zero duration.
        result = CommandResult(outcome="completed")
        assert result.stdout == ""
        assert result.stderr == ""
        assert result.exit_code is None
        assert result.resolved_command == ""
        assert result.start_error is None
        assert result.duration_seconds == 0.0

    def test_start_error_defaults(self) -> None:
        # Requirement: errno/filename are optional metadata of a start error.
        error = StartError(kind="os_error", message="boom")
        assert error.errno is None
        assert error.filename is None

    def test_workspace_lease_and_run_spec_defaults(self) -> None:
        # Requirement: lease location and workflow name are optional hints.
        assert WorkspaceLease(lease_id="r1", backend="local", incarnation="i1").location is None
        assert RunSpec(run_id="r1").workflow_name is None


class TestProtocolShape:
    """Requirement: ``RunnerBackend`` is a typing.Protocol, not a base class."""

    def test_runner_backend_is_a_protocol(self) -> None:
        # Requirement: structural typing — backends need not inherit anything.
        assert getattr(RunnerBackend, "_is_protocol", False) is True

    def test_protocol_declares_exactly_four_methods(self) -> None:
        # Requirement: the seam stays minimal — no run_agent/open_mcp/cancel,
        # no close(), no context manager "for symmetry".
        method_names = {
            name
            for name, member in vars(RunnerBackend).items()
            if callable(member) and not name.startswith("_")
        }
        assert method_names == {"capabilities", "prepare_run", "run_command", "finalize_run"}


class TestLeafPurity:
    """Requirement: ``conductor.execution`` imports nothing from Conductor."""

    def test_import_does_not_pull_conductor_layers(self) -> None:
        # Requirement: leaf purity — importing the contract package must not
        # transitively import conductor.cli/engine/executor. Subprocess
        # isolation is load-bearing: an in-process sys.modules check would be
        # polluted by the test session's own imports.
        repo_src = Path(__file__).resolve().parents[2] / "src"
        env = {**os.environ, "PYTHONPATH": str(repo_src)}
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import sys\n"
                    "import conductor.execution  # noqa: F401\n"
                    "forbidden = ('conductor.cli', 'conductor.engine', 'conductor.executor')\n"
                    "leaked = [m for m in forbidden if m in sys.modules]\n"
                    "assert not leaked, f'conductor.execution pulled in: {leaked}'\n"
                    "print('leaf-pure')\n"
                ),
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )
        assert proc.returncode == 0, proc.stderr
        assert "leaf-pure" in proc.stdout

    def test_package_modules_import_only_stdlib(self) -> None:
        # Requirement: leaf purity, negative control at the AST level — this
        # fails if any conductor import (executor/cli/engine/...) sneaks into
        # the package, even one a subprocess smoke test might not exercise.
        import ast

        package_dir = Path(__file__).resolve().parents[2] / "src" / "conductor" / "execution"
        offenders: list[str] = []
        for source_path in sorted(package_dir.glob("*.py")):
            tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
            for node in ast.walk(tree):
                imported: str | None = None
                if isinstance(node, ast.Import):
                    imported = node.names[0].name
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported = node.module
                if imported is None or not imported.startswith("conductor"):
                    continue
                is_self = imported == "conductor.execution" or imported.startswith(
                    "conductor.execution."
                )
                if not is_self:
                    offenders.append(f"{source_path.name}:{node.lineno}:{imported}")
        assert offenders == []


class TestLiteralVocabularies:
    """Requirement: outcome/kind vocabularies are Literals in house style."""

    def test_command_outcome_values(self) -> None:
        # Requirement: the four command outcomes, and no more.
        assert get_args(CommandOutcome) == (
            "completed",
            "command_not_found",
            "start_failed",
            "timed_out",
        )

    def test_run_outcome_values(self) -> None:
        # Requirement: run outcomes distinguish success, failure, cancellation.
        assert get_args(RunOutcome) == ("succeeded", "failed", "cancelled")

    def test_start_error_kind_values(self) -> None:
        # Requirement: exactly the two OSError branches the executor chains.
        assert get_args(StartErrorKind) == ("file_not_found", "os_error")

    def test_start_error_kind_is_literal(self) -> None:
        # Requirement: kind is typed as the Literal alias, not a free str.
        kind_field = next(f for f in dataclasses.fields(StartError) if f.name == "kind")
        assert kind_field.type == "StartErrorKind"
        assert get_args(StartErrorKind) == ("file_not_found", "os_error")


class TestStartErrorRoundTrip:
    """Requirement: StartError reconstructs the original exception for chaining."""

    @pytest.mark.parametrize(
        "original",
        [
            FileNotFoundError(2, "No such file or directory", "no-such-cmd"),
            PermissionError(13, "Permission denied", "/root/secret.sh"),
            OSError(98, "Address already in use"),
        ],
    )
    def test_errno_bearing_round_trip(self, original: OSError) -> None:
        # Requirement: with a structured errno the reconstructed exception
        # matches the original on type/str/errno/filename (CPython's
        # OSError(errno, ...) constructor auto-selects the built-in subclass,
        # e.g. PermissionError for errno 13).
        start_error = _fill_start_error(original)
        reconstructed = _reconstruct_cause(start_error)
        assert type(reconstructed) is type(original)
        assert str(reconstructed) == str(original)
        assert reconstructed.errno == original.errno
        assert reconstructed.filename == original.filename
        assert start_error.message == (
            original.strerror if original.errno is not None else str(original)
        )

    def test_errno_free_round_trip(self) -> None:
        # Requirement: without an errno the fill uses str(e) and the rebuild
        # passes the message positionally — no fabricated errno appears.
        original = FileNotFoundError("no errno at all")
        assert original.errno is None
        start_error = _fill_start_error(original)
        assert start_error.kind == "file_not_found"
        assert start_error.errno is None
        assert start_error.message == str(original)
        reconstructed = _reconstruct_cause(start_error)
        assert type(reconstructed) is FileNotFoundError
        assert str(reconstructed) == str(original)
        assert reconstructed.errno is None

    def test_kind_classification(self) -> None:
        # Requirement: FileNotFoundError maps to "file_not_found", any other
        # OSError to "os_error".
        assert _fill_start_error(FileNotFoundError(2, "nope", "x")).kind == "file_not_found"
        assert _fill_start_error(OSError(5, "io error", "y")).kind == "os_error"

    def test_no_raw_exception_in_contract(self) -> None:
        # Requirement: raw exception objects never appear in the contract —
        # every StartError field is plain serializable data.
        error = _fill_start_error(PermissionError(13, "Permission denied", "/tmp/x"))
        for field in dataclasses.fields(error):
            value = getattr(error, field.name)
            assert not isinstance(value, BaseException)


def test_aliases_are_typing_literals() -> None:
    # Requirement: outcomes are plain data (Literal aliases), not enums or
    # exception subclasses — house style, see RunMode in fleet/records.py.
    assert CommandOutcome.__origin__ is Literal  # type: ignore[attr-defined]
    assert RunOutcome.__origin__ is Literal  # type: ignore[attr-defined]
