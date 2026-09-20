"""Local-process implementation of the runner backend contract."""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import time
from collections.abc import Callable
from typing import cast
from uuid import uuid4

from conductor.execution.types import (
    CommandResult,
    CommandSpec,
    RunnerCapabilities,
    RunOutcome,
    RunSpec,
    StartError,
    WorkspaceLease,
)


class LocalRunnerBackend:
    """Run commands as child processes on the local machine."""

    def capabilities(self) -> RunnerCapabilities:
        """Declare local batch execution with a shared workspace."""
        return RunnerCapabilities(
            batch=True,
            sessions=False,
            shared_workspace=True,
            snapshots=False,
        )

    async def prepare_run(self, run: RunSpec) -> WorkspaceLease:
        """Create an opaque local workspace handle for a run."""
        return WorkspaceLease(
            lease_id=run.run_id,
            backend="local",
            incarnation=uuid4().hex[:12],
            location=None,
        )

    async def finalize_run(self, lease: WorkspaceLease, outcome: RunOutcome) -> None:
        """Finalize a local run.

        Local execution owns no run-scoped resources to release. Remote
        backends use this lifecycle point to clean up their execution realm.
        """
        del lease, outcome

    async def run_command(
        self,
        spec: CommandSpec,
        lease: WorkspaceLease | None,
        *,
        diagnostics: Callable[[str], None] | None = None,
    ) -> CommandResult:
        """Run one command locally and return its data-shaped outcome."""
        del lease
        started_at = time.monotonic()

        # Build environment (merge os.environ + declared overrides).
        # Always set PYTHONUTF8=1 so child Python processes use UTF-8 encoding
        # instead of the system default (cp1252 on Windows), preventing garbled
        # Unicode characters in script output.
        if spec.inherit_control_environment:
            env = {**os.environ, "PYTHONUTF8": "1", **spec.env}
        else:
            env = {"PYTHONUTF8": "1", **spec.env}

        # Resolve bare command names and absolute paths against PATH so that a
        # bare name (e.g. "python") finds the executable the shell would, and a
        # path missing an extension resolves correctly. Resolution uses the
        # subprocess's own ``PATH`` (``env`` may override it via ``spec.env``),
        # so the resolved binary matches the one the child would have executed.
        # Relative paths containing a separator are left untouched so they keep
        # resolving against ``working_dir``. Resolution is non-destructive: when
        # ``which`` cannot resolve the command we fall back to the rendered value.
        resolved_command = spec.command
        has_separator = os.sep in resolved_command or (
            os.altsep is not None and os.altsep in resolved_command
        )
        if os.path.isabs(resolved_command) or not has_separator:
            resolved_command = (
                shutil.which(resolved_command, path=env.get("PATH")) or resolved_command
            )

        if diagnostics is not None:
            diagnostics(f"  Script: {resolved_command} {' '.join(spec.args)}")
            if spec.stdin is not None:
                diagnostics(f"  Script stdin: {len(spec.stdin)} bytes")

        try:
            process = await asyncio.create_subprocess_exec(
                resolved_command,
                *spec.args,
                stdin=asyncio.subprocess.PIPE if spec.stdin is not None else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=spec.working_dir,
                env=env,
            )
        except FileNotFoundError as exc:
            return CommandResult(
                outcome="command_not_found",
                resolved_command=resolved_command,
                start_error=StartError(
                    kind="file_not_found",
                    message=cast(str, exc.strerror) if exc.errno is not None else str(exc),
                    errno=exc.errno,
                    filename=cast(str | None, exc.filename),
                ),
                duration_seconds=time.monotonic() - started_at,
            )
        except OSError as exc:
            return CommandResult(
                outcome="start_failed",
                resolved_command=resolved_command,
                start_error=StartError(
                    kind="os_error",
                    message=cast(str, exc.strerror) if exc.errno is not None else str(exc),
                    errno=exc.errno,
                    filename=cast(str | None, exc.filename),
                ),
                duration_seconds=time.monotonic() - started_at,
            )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(input=spec.stdin), timeout=spec.timeout
            )
        except TimeoutError:
            process.kill()
            await process.wait()
            return CommandResult(
                outcome="timed_out",
                resolved_command=resolved_command,
                duration_seconds=time.monotonic() - started_at,
            )
        except asyncio.CancelledError:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            with contextlib.suppress(BaseException):
                await process.wait()
            raise

        stdout_text = stdout_bytes.decode("utf-8", errors="replace")
        stderr_text = stderr_bytes.decode("utf-8", errors="replace")

        if stderr_text and diagnostics is not None:
            diagnostics(f"  Script stderr: {stderr_text.strip()}")

        # ``returncode`` is guaranteed non-None after ``communicate``.
        assert process.returncode is not None
        return CommandResult(
            outcome="completed",
            stdout=stdout_text,
            stderr=stderr_text,
            exit_code=process.returncode,
            resolved_command=resolved_command,
            duration_seconds=time.monotonic() - started_at,
        )
