"""The resolved run manifest: a deterministic snapshot of execution resolution.

``compile_run_manifest`` resolves every executable step of the *root* workflow
configuration to a concrete runner backend through an execution environment
document and pins the result in a :class:`ResolvedRunManifest`. The manifest is
**run-invariant**: it deliberately contains no run id, no timestamps, no
inputs, no CLI overrides, and no absolute paths, so two compilations of the
same inputs produce byte-identical ``model_dump(mode="json")`` output and the
manifest can act as the audit record of *how* a run was set up to execute.

**Execution-step identity.** The keys of ``ResolvedRunManifest.profiles`` are:

* ``<name>`` for top-level executable steps (agent, script, mcp, workflow)
  declared in ``config.agents`` — e.g. ``inspect``.
* ``for_each.<group_name>.agent`` for the inline agent of a for-each group —
  e.g. ``for_each.repos.agent``.

The qualified for-each key keeps two inline agents that share one step name in
different groups distinct (``for_each.first.agent`` vs
``for_each.second.agent``). No name-uniqueness validation is performed here:
duplicate step names silently collapse to one key, matching the engine's
existing name-resolution semantics — this module records resolution, it does
not tighten the schema.

**Scope boundary.** Only the root configuration is compiled into the manifest.
Nested sub-workflow steps (the file a ``type: workflow`` step points at) are
*not* included: a sub-workflow engine compiles its own view over its own
configuration when it is constructed at reach time, so a root manifest never
claims resolution authority over configuration it has not read.

**Audit posture.** Every manifest carries an :class:`AuditInfo` classifying
itself as ``non-hermetic-compatibility``: resolved profiles and backends may
depend on machine-local environment documents, so the manifest pins what was
resolved (names, digests, content hashes) rather than pretending the
resolution was hermetic.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from conductor.config.environment import ResolvedEnvironment
from conductor.config.schema import (
    ExecutableStepBase,
    ScriptStepDef,
    WorkflowConfig,
)
from conductor.exceptions import ConfigurationError
from conductor.execution import LocalRunnerBackend, RunnerBackend

# Capability-introspection registry: backend name -> a backend instance asked
# only for its static ``capabilities()`` declaration. The instances are
# assumed STATELESS with respect to capabilities — the answer must not depend
# on when it is asked, because the manifest compiler asks at compile time and
# the run may ask again later. ``LocalRunnerBackend`` satisfies this today (it
# has no instance state at all); any future backend registered here must too.
BACKEND_CAPABILITY_PROVIDERS: dict[str, RunnerBackend] = {
    "local": LocalRunnerBackend(),
}


class WorkflowIdentity(BaseModel):
    """Identity of the workflow being run.

    ``digest`` is ``sha256:<hex>`` over the workflow file's bytes, or ``None``
    when the workflow was built without a file on disk (programmatic
    construction) — there is nothing to hash.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str | None
    digest: str | None


class EnvironmentIdentity(BaseModel):
    """Identity of the execution environment the profiles resolved against."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    source: Literal["builtin", "path", "project", "user"]
    digest: str


class ResolvedStepProfile(BaseModel):
    """One executable step's resolved execution profile and backend."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    profile: str
    backend: str


class AuditInfo(BaseModel):
    """Self-classification of the manifest's hermetic posture.

    ``hermetic`` is a literal ``False``: resolution depends on machine-local
    environment documents, so the manifest pins resolved names and digests
    instead of claiming hermetic reproducibility. ``classification`` is the
    stable label downstream tooling keys on.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    hermetic: Literal[False]
    classification: Literal["non-hermetic-compatibility"]


class ResolvedRunManifest(BaseModel):
    """The compiled, run-invariant execution manifest for one workflow run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1]
    workflow: WorkflowIdentity
    environment: EnvironmentIdentity
    profiles: dict[str, ResolvedStepProfile]
    conductor_version: str
    audit: AuditInfo


def _conductor_version() -> str:
    """Return the installed conductor-cli version.

    Mirrors ``WorkflowEngine._conductor_version``: ``conductor.__version__``
    is itself sourced from ``importlib.metadata``, with ``"unknown"`` as the
    fallback when the distribution metadata cannot be read.
    """
    try:
        from conductor import __version__

        return __version__
    except Exception:
        return "unknown"


def _iter_executable_steps(config: WorkflowConfig) -> list[tuple[str, ExecutableStepBase]]:
    """Collect ``(identity_key, step)`` for every executable step of the root config.

    Top-level executable steps key by their bare ``name``; inline for-each
    agents key by ``for_each.<group_name>.agent`` (see the module docstring).
    Engine-local steps (set, wait, terminate, human_gate, questions) are not
    executable and are skipped.
    """
    steps: list[tuple[str, ExecutableStepBase]] = []
    for step in config.agents:
        if isinstance(step, ExecutableStepBase):
            steps.append((step.name, step))
    for group in config.for_each:
        agent = group.agent
        if isinstance(agent, ExecutableStepBase):
            steps.append((f"for_each.{group.name}.agent", agent))
    return steps


def _resolve_profile_name(
    key: str,
    step: ExecutableStepBase,
    config: WorkflowConfig,
    environment: ResolvedEnvironment,
) -> str:
    """Resolve the profile name for one step through the precedence chain.

    Chain, first hit wins:

    1. ``step.execution.profile``
    2. ``config.workflow.defaults.execution.profile``
    3. ``environment.document.default``

    A complete miss is a configuration error naming the step and the full
    chain, so the author sees every level that failed rather than guessing.
    """
    step_profile = step.execution.profile if step.execution is not None else None
    if step_profile is not None:
        return step_profile

    defaults = config.workflow.defaults.execution
    workflow_profile = defaults.profile if defaults is not None else None
    if workflow_profile is not None:
        return workflow_profile

    if environment.document.default is not None:
        return environment.document.default

    raise ConfigurationError(
        f"Step '{key}' names no execution profile and none can be resolved. "
        "Precedence chain exhausted: "
        "step 'execution.profile' is unset, "
        "'workflow.defaults.execution.profile' is unset, "
        f"and environment '{environment.name}' defines no 'default' profile.",
        suggestion="Set 'execution.profile' on the step, add "
        "'workflow.defaults.execution.profile', or give the environment "
        "document a 'default' profile.",
    )


def _require_script_backend_capability(key: str, backend_name: str) -> None:
    """Enforce that a script step's backend can run plain commands.

    ``ScriptStepDef`` delegates to the backend's batch execution, so a backend
    without ``capabilities().batch`` cannot serve the step and compilation
    fails fast with a ``ConfigurationError`` naming the step, the backend, and
    the missing capability.
    """
    provider = BACKEND_CAPABILITY_PROVIDERS.get(backend_name)
    if provider is None or not provider.capabilities().batch:
        raise ConfigurationError(
            f"Script step '{key}' resolves to backend '{backend_name}', which "
            "does not declare the 'batch' capability required to run commands.",
            suggestion="Map the step's execution profile to a backend that "
            "supports batch execution in this build of Conductor.",
        )


def compile_run_manifest(
    config: WorkflowConfig,
    *,
    workflow_path: Path | None,
    environment: ResolvedEnvironment,
) -> ResolvedRunManifest:
    """Compile the run-invariant execution manifest for a workflow configuration.

    Pure function: the same inputs always produce the same manifest. Each
    executable step of the root config is resolved through the precedence
    chain (see :func:`_resolve_profile_name`) to a profile defined in
    ``environment.document.profiles``; script steps are additionally checked
    against the backend's batch capability (see
    :func:`_require_script_backend_capability`).

    Args:
        config: The parsed root workflow configuration.
        workflow_path: Path to the workflow file, or ``None`` when the config
            was built without one (digest becomes ``None``).
        environment: The resolved execution environment the profiles resolve
            against.

    Returns:
        The compiled manifest. ``model_dump(mode="json")`` is byte-identical
        across calls with equal inputs.

    Raises:
        ConfigurationError: If any step's profile cannot be resolved through
            the chain, names an undefined profile, or (for script steps)
            resolves to a backend without batch capability.
    """
    profiles: dict[str, ResolvedStepProfile] = {}
    for key, step in _iter_executable_steps(config):
        profile_name = _resolve_profile_name(key, step, config, environment)
        definition = environment.document.profiles.get(profile_name)
        if definition is None:
            available = ", ".join(sorted(environment.document.profiles))
            raise ConfigurationError(
                f"Step '{key}' names execution profile '{profile_name}', which "
                f"is not defined in environment '{environment.name}' "
                f"(defined profiles: {available}).",
                suggestion="Define the profile in the environment document, or "
                "point the step at one of the defined profiles.",
            )
        backend_name = definition.backend
        if isinstance(step, ScriptStepDef):
            _require_script_backend_capability(key, backend_name)
        profiles[key] = ResolvedStepProfile(profile=profile_name, backend=backend_name)

    digest: str | None = None
    if workflow_path is not None:
        digest = f"sha256:{hashlib.sha256(workflow_path.read_bytes()).hexdigest()}"

    return ResolvedRunManifest(
        version=1,
        workflow=WorkflowIdentity(name=config.workflow.name, digest=digest),
        environment=EnvironmentIdentity(
            name=environment.name,
            source=environment.source,
            digest=environment.digest,
        ),
        profiles=profiles,
        conductor_version=_conductor_version(),
        audit=AuditInfo(hermetic=False, classification="non-hermetic-compatibility"),
    )
