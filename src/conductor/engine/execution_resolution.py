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
from conductor.engine.run_manifest import (
    ResolvedRunManifest,
    compile_run_manifest,
    executable_step_identity,
)
from conductor.engine.secrets import (
    IndexedSecretUse,
    SecretUseIndex,
    SecretValueCache,
    index_config,
)
from conductor.execution import (
    LocalRunnerBackend,
    RunnerBackend,
    RunOutcome,
    RunSpec,
    WorkspaceLease,
)
from conductor.redaction import RunRedactor

logger = logging.getLogger(__name__)


class ExecutionResolverSession:
    """Run-shared backend instances and their prepared workspace leases."""

    def __init__(
        self,
        environment: ResolvedEnvironment,
        default_backend: RunnerBackend | None = None,
        secret_cache: SecretValueCache | None = None,
        redactor: RunRedactor | None = None,
    ) -> None:
        """Create a session seeded with the run's local backend instance.

        Secret-primitive pairing: when a ``secret_cache`` is injected without
        a redactor, the session redactor is derived from the cache (the one
        its values are registered into) so runtime sinks scrub exactly the
        values the cache resolved. An explicitly injected ``(cache, redactor)``
        pair whose two members are not the same objects is a wiring bug:
        delivered values would be registered into one redactor while sinks
        scrub with the other, so it is rejected here rather than discovered
        as an unredacted leak later.
        """
        self.environment = environment
        self.backends: dict[str, RunnerBackend] = {
            "local": default_backend or LocalRunnerBackend(),
        }
        self.leases: dict[str, WorkspaceLease] = {}
        self._owns_secrets = secret_cache is None
        if secret_cache is not None:
            if redactor is not None and secret_cache.redactor is not redactor:
                raise ValueError(
                    "secret_cache and redactor must belong to the same run pair "
                    "(the cache's redactor is the one its resolved values are "
                    "registered into); derive the session redactor from the "
                    "injected cache instead of passing a separate instance."
                )
            self._redactor = secret_cache.redactor
        else:
            self._redactor = redactor
        self._secret_cache = secret_cache

    @property
    def owns_secrets(self) -> bool:
        """Whether this session owns secret cleanup rather than its caller."""
        return self._owns_secrets

    @property
    def redactor(self) -> RunRedactor:
        """Return the run redactor, creating the self-owned pair lazily."""
        self._ensure_secrets()
        assert self._redactor is not None
        return self._redactor

    @property
    def secret_cache(self) -> SecretValueCache:
        """Return the run secret cache, creating the self-owned pair lazily."""
        self._ensure_secrets()
        assert self._secret_cache is not None
        return self._secret_cache

    def _ensure_secrets(self) -> None:
        """Create missing run-scoped secret primitives for direct engine users."""
        if self._redactor is None:
            self._redactor = RunRedactor()
        if self._secret_cache is None:
            self._secret_cache = SecretValueCache(self.environment, self._redactor)

    def reset_secrets(self) -> None:
        """Clear self-owned secret state before a new run generation."""
        if not self._owns_secrets:
            return
        self.secret_cache.clear()
        self.redactor.clear()

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

        if self._owns_secrets:
            self.reset_secrets()
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
        self._config = config
        self.publish_manifest = publish_manifest
        self._manifest = compile_run_manifest(
            config,
            workflow_path=workflow_path,
            environment=session.environment,
        )
        self._secret_uses = index_config(config, session.secret_cache)

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
        key = executable_step_identity(name, for_each_group=for_each_group)
        backend_name = self._manifest.profiles[key].backend
        return self._session.backends[backend_name]

    def refresh_secret_uses(self) -> None:
        """Re-resolve this view's secret uses for a new run generation."""
        self._secret_uses = index_config(self._config, self._session.secret_cache)

    def inherit_env_for_step(
        self,
        name: str,
        *,
        for_each_group: str | None = None,
    ) -> bool:
        """Return the compiled control-environment inheritance policy."""
        key = executable_step_identity(name, for_each_group=for_each_group)
        return self._manifest.profiles[key].inherit_control_environment

    def secret_env_for_step(
        self,
        name: str,
        *,
        for_each_group: str | None = None,
    ) -> dict[str, str]:
        """Return this view's environment deliveries for one step."""
        key = executable_step_identity(name, for_each_group=for_each_group)
        return self._secret_uses.secret_env_for_step(key)

    def deliveries_for_server(self, name: str) -> tuple[IndexedSecretUse, ...]:
        """Return this view's secret deliveries for one MCP server."""
        return self._secret_uses.deliveries_for_server(name)

    @property
    def secret_uses(self) -> SecretUseIndex:
        """This view's per-config secret-use index.

        Exposed so MCP configuration resolution (``type: mcp`` steps connect
        in the engine, not the CLI) can deliver this config's declared secret
        values, exactly as ``_build_mcp_servers`` does for the provider
        connection path. Values are read through the cache at delivery time;
        the index itself never holds plaintext.
        """
        return self._secret_uses
