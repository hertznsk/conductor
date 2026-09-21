"""Run-shared execution state and per-engine resolution views.

An :class:`ExecutionResolverSession` owns backend instances and workspace
leases for one run. Each root or child workflow gets its own
:class:`ExecutionResolver` view over that shared session, so nested workflow
configuration is compiled only when the child engine is constructed while all
steps in the run still use the same backend instances and leases.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from conductor.config.environment import ResolvedEnvironment
from conductor.config.schema import WorkflowConfig
from conductor.engine.run_manifest import ResolvedRunManifest, compile_run_manifest
from conductor.execution import (
    LocalRunnerBackend,
    RunnerBackend,
    RunOutcome,
    RunSpec,
    WorkspaceLease,
)

logger = logging.getLogger(__name__)


class ExecutionResolverSession:
    """Run-shared backend instances and their prepared workspace leases."""

    def __init__(
        self,
        environment: ResolvedEnvironment,
        default_backend: RunnerBackend | None = None,
    ) -> None:
        """Create a session seeded with the run's local backend instance."""
        self.environment = environment
        self.backends: dict[str, RunnerBackend] = {
            "local": default_backend or LocalRunnerBackend(),
        }
        self.leases: dict[str, WorkspaceLease] = {}

    async def prepare_leases(self, run_spec: RunSpec) -> None:
        """Prepare one lease per distinct backend, idempotently."""
        leases_by_backend: dict[int, WorkspaceLease] = {
            id(self.backends[name]): lease for name, lease in self.leases.items()
        }
        for name, backend in self.backends.items():
            lease = leases_by_backend.get(id(backend))
            if lease is None:
                lease = await backend.prepare_run(run_spec)
                leases_by_backend[id(backend)] = lease
            self.leases[name] = lease

    def lease_for_backend(self, name: str) -> WorkspaceLease | None:
        """Return the prepared lease for ``name``, if one exists."""
        return self.leases.get(name)

    async def finalize_leases(self, outcome: RunOutcome) -> None:
        """Best-effort finalize every prepared lease without masking outcomes.

        Leases are detached before cleanup starts, preventing a repeated run
        from reusing or double-finalizing a handle. Cleanup is shielded from a
        racing cancellation; cancellation is re-raised only after every
        backend has had its chance to finalize.
        """
        leases = self.leases
        self.leases = {}
        cancelled = False
        finalized_backends: set[int] = set()

        for name, lease in leases.items():
            backend = self.backends[name]
            if id(backend) in finalized_backends:
                continue
            finalized_backends.add(id(backend))
            finalize_task = asyncio.ensure_future(backend.finalize_run(lease, outcome))
            while True:
                try:
                    await asyncio.shield(finalize_task)
                    break
                except asyncio.CancelledError:
                    cancelled = True
                    if finalize_task.done():
                        break
                except Exception:
                    logger.warning(
                        "Execution backend '%s' finalize_run failed (outcome=%s); "
                        "the run outcome is unaffected.",
                        name,
                        outcome,
                        exc_info=True,
                    )
                    break

        if cancelled:
            raise asyncio.CancelledError


class ExecutionResolver:
    """Per-engine execution-resolution view over a run-shared session."""

    def __init__(
        self,
        config: WorkflowConfig,
        session: ExecutionResolverSession,
        *,
        workflow_path: Path | None,
        publish_manifest: bool,
    ) -> None:
        """Compile this engine's step map immediately from its own config."""
        self._session = session
        self.publish_manifest = publish_manifest
        self._manifest = compile_run_manifest(
            config,
            workflow_path=workflow_path,
            environment=session.environment,
        )

    @property
    def manifest(self) -> ResolvedRunManifest:
        """Return this engine view's compiled execution manifest."""
        return self._manifest

    def backend_for_step(
        self,
        name: str,
        *,
        for_each_group: str | None = None,
    ) -> RunnerBackend:
        """Return the backend resolved for a top-level or inline step."""
        key = f"for_each.{for_each_group}.agent" if for_each_group is not None else name
        backend_name = self._manifest.profiles[key].backend
        return self._session.backends[backend_name]
