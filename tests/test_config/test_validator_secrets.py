"""Validator cross-checks for secret references: structural, explicit, ambient."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal, cast
from unittest.mock import ANY, patch

import pytest

from conductor.config.environment import (
    EnvironmentDocument,
    ProfileDefinition,
    ResolvedEnvironment,
    SecretBinding,
    SecretBindingSource,
)
from conductor.config.schema import (
    AgentDef,
    ForEachDef,
    MCPServerDef,
    OutputField,
    RouteDef,
    RuntimeConfig,
    ScriptStepDef,
    SecretDelivery,
    StepExecutionConfig,
    StepSecretRef,
    WorkflowConfig,
    WorkflowDef,
    WorkflowDefaults,
)
from conductor.config.validator import validate_workflow_config
from conductor.exceptions import ConfigurationError


def _secret(
    ref: str,
    scope: Literal["script", "mcp", "agent"],
    *,
    env: str | None = None,
    header: str | None = None,
) -> StepSecretRef:
    return StepSecretRef(ref=ref, scope=scope, delivery=SecretDelivery(env=env, header=header))


def _binding(
    env_var: str,
    allow: list[Literal["script", "mcp"]] | None = None,
) -> SecretBinding:
    return SecretBinding(source=SecretBindingSource(env=env_var), allow=allow)


def _environment(
    secrets: dict[str, SecretBinding] | None = None,
    *,
    name: str = "test-env",
) -> ResolvedEnvironment:
    document = EnvironmentDocument(
        default="default",
        profiles={"default": ProfileDefinition(backend="local")},
        secrets=secrets,
    )
    return ResolvedEnvironment(
        document=document,
        name=name,
        source="path",
        path=None,
        digest="sha256:test",
    )


def _alpha_beta_environment() -> ResolvedEnvironment:
    return _environment(
        {
            "alpha": _binding("CONDUCTOR_TEST_TASK10_ALPHA"),
            "beta": _binding("CONDUCTOR_TEST_TASK10_BETA"),
        }
    )


def _script_config(
    *secrets: StepSecretRef,
    env: dict[str, str] | None = None,
) -> WorkflowConfig:
    return WorkflowConfig(
        workflow=WorkflowDef(name="script-secrets", entry_point="run"),
        agents=[
            ScriptStepDef(
                name="run",
                command="echo",
                env=env or {},
                execution=StepExecutionConfig(secrets=list(secrets)),
                routes=[RouteDef(to="$end")],
            )
        ],
        output={"result": "{{ run.output.stdout }}"},
    )


def _agent_config(*secrets: StepSecretRef) -> WorkflowConfig:
    return WorkflowConfig(
        workflow=WorkflowDef(name="agent-secrets", entry_point="agent"),
        agents=[
            AgentDef(
                name="agent",
                model="gpt-4",
                prompt="test",
                output={"value": OutputField(type="string")},
                execution=StepExecutionConfig(secrets=list(secrets)),
                routes=[RouteDef(to="$end")],
            )
        ],
        output={"result": "{{ agent.output.value }}"},
    )


def _mcp_config(server: MCPServerDef) -> WorkflowConfig:
    return WorkflowConfig(
        workflow=WorkflowDef(
            name="mcp-secrets",
            entry_point="agent",
            runtime=RuntimeConfig(mcp_servers={"server": server}),
        ),
        agents=[
            AgentDef(
                name="agent",
                model="gpt-4",
                prompt="test",
                output={"value": OutputField(type="string")},
                routes=[RouteDef(to="$end")],
            )
        ],
        output={"result": "{{ agent.output.value }}"},
    )


def _explicit_context(environment: ResolvedEnvironment, root: Path) -> dict[str, Any]:
    return {
        "refs_found": False,
        "environments": {environment.name: environment},
        "explicit": True,
        "root_workflow_dir": root,
        "warned_no_environments": False,
        "warned_no_secret_environments": False,
    }


def _validate_explicit(
    config: WorkflowConfig,
    environment: ResolvedEnvironment,
    tmp_path: Path,
) -> list[str]:
    return validate_workflow_config(
        config,
        workflow_path=tmp_path / "workflow.yaml",
        _environment_context=cast(Any, _explicit_context(environment, tmp_path)),
    )


class TestScopeVsPosition:
    """Structural checks mirroring the manifest compiler's fail-fast choke."""

    def test_script_step_rejects_mcp_scope(self, tmp_path: Path) -> None:
        # Requirement: a secret attached to a script position must declare script scope.
        config = _script_config(_secret("alpha", "mcp", env="TOKEN"))
        with pytest.raises(ConfigurationError, match="position requires scope 'script'"):
            _validate_explicit(config, _alpha_beta_environment(), tmp_path)

    def test_agent_step_with_secrets_is_reserved_until_step_7(self, tmp_path: Path) -> None:
        # Requirement: any secret on a non-script step errors, mentioning step 7.
        config = _agent_config(_secret("alpha", "script", env="TOKEN"))
        with pytest.raises(ConfigurationError, match=r"agent-scope delivery is reserved.*step 7"):
            _validate_explicit(config, _alpha_beta_environment(), tmp_path)

    def test_script_step_rejects_agent_scope(self, tmp_path: Path) -> None:
        # Requirement: explicit agent scope anywhere errors, mentioning step 7.
        config = _script_config(_secret("alpha", "agent", env="TOKEN"))
        with pytest.raises(ConfigurationError, match=r"agent-scope delivery is reserved.*step 7"):
            _validate_explicit(config, _alpha_beta_environment(), tmp_path)

    def test_mcp_server_rejects_script_scope(self, tmp_path: Path) -> None:
        # Requirement: a secret attached to an MCP server must declare mcp scope.
        server = MCPServerDef(command="server", secrets=[_secret("alpha", "script", env="TOKEN")])
        with pytest.raises(ConfigurationError, match="position requires scope 'mcp'"):
            _validate_explicit(_mcp_config(server), _alpha_beta_environment(), tmp_path)

    def test_mcp_server_rejects_agent_scope(self, tmp_path: Path) -> None:
        # Requirement: agent scope on an MCP server errors, mentioning step 7.
        server = MCPServerDef(command="server", secrets=[_secret("alpha", "agent", env="TOKEN")])
        with pytest.raises(ConfigurationError, match=r"agent-scope delivery is reserved.*step 7"):
            _validate_explicit(_mcp_config(server), _alpha_beta_environment(), tmp_path)

    def test_script_step_rejects_header_delivery(self, tmp_path: Path) -> None:
        # Requirement: HTTP header delivery is valid only at an MCP server use-site.
        config = _script_config(_secret("alpha", "script", header="Authorization"))
        with pytest.raises(ConfigurationError, match="header delivery is MCP-only"):
            _validate_explicit(config, _alpha_beta_environment(), tmp_path)

    def test_stdio_server_rejects_header_delivery_naming_transport(self, tmp_path: Path) -> None:
        # Requirement: stdio servers cannot receive headers; the error names the transport.
        server = MCPServerDef(
            command="server",
            secrets=[_secret("alpha", "mcp", header="Authorization")],
        )
        with pytest.raises(ConfigurationError, match=r"transport 'stdio'"):
            _validate_explicit(_mcp_config(server), _alpha_beta_environment(), tmp_path)

    def test_http_server_accepts_header_delivery(self, tmp_path: Path) -> None:
        # Requirement: header delivery over an HTTP transport is a valid use-site.
        server = MCPServerDef(
            type="http",
            url="https://example.test/mcp",
            secrets=[_secret("alpha", "mcp", header="Authorization")],
        )
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv("CONDUCTOR_TEST_TASK10_ALPHA", "x")
            monkeypatch.setenv("CONDUCTOR_TEST_TASK10_BETA", "x")
            warnings = _validate_explicit(_mcp_config(server), _alpha_beta_environment(), tmp_path)
        assert warnings == []

    def test_for_each_inline_agent_secrets_error_names_the_group(self, tmp_path: Path) -> None:
        # Requirement: an inline for-each agent's consumer label matches the
        # manifest identity key (``for_each.<group>.agent``).
        config = WorkflowConfig(
            workflow=WorkflowDef(name="fe", entry_point="start"),
            agents=[AgentDef(name="start", prompt="x", routes=[RouteDef(to="$end")])],
            for_each=[
                ForEachDef(
                    name="batch",
                    type="for_each",
                    source="workflow.input.items",
                    agent=AgentDef(
                        name="worker",
                        model="gpt-4",
                        prompt="work",
                        execution=StepExecutionConfig(
                            secrets=[_secret("alpha", "script", env="TOKEN")]
                        ),
                    ),
                    **{"as": "item"},
                )
            ],
            output={"result": "{{ start.output.value }}"},
        )
        with pytest.raises(ConfigurationError, match=r"for_each\.batch\.agent.*step 7"):
            _validate_explicit(config, _alpha_beta_environment(), tmp_path)


class TestDeliveryCollisions:
    """Delivery-name collisions within one consumer."""

    def test_script_literal_env_collides_with_binding(self, tmp_path: Path) -> None:
        # Requirement: a literal script ``env:`` name and a binding delivery share
        # one namespace, so a collision is an error.
        config = _script_config(_secret("alpha", "script", env="TOKEN"), env={"TOKEN": "literal"})
        with pytest.raises(ConfigurationError, match="collides within consumer 'run'"):
            _validate_explicit(config, _alpha_beta_environment(), tmp_path)

    def test_two_bindings_collide_on_env_name(self, tmp_path: Path) -> None:
        # Requirement: two bindings delivering to the same env name collide.
        config = _script_config(
            _secret("alpha", "script", env="TOKEN"),
            _secret("beta", "script", env="TOKEN"),
        )
        with pytest.raises(ConfigurationError, match="collides within consumer 'run'"):
            _validate_explicit(config, _alpha_beta_environment(), tmp_path)

    def test_mcp_server_literal_env_collides_with_binding(self, tmp_path: Path) -> None:
        # Requirement: a literal server ``env:`` name collides with a binding delivery.
        server = MCPServerDef(
            command="server",
            env={"TOKEN": "literal"},
            secrets=[_secret("alpha", "mcp", env="TOKEN")],
        )
        with pytest.raises(ConfigurationError, match="collides within consumer 'mcp:server'"):
            _validate_explicit(_mcp_config(server), _alpha_beta_environment(), tmp_path)

    def test_header_collision_is_always_case_insensitive(self, tmp_path: Path) -> None:
        # Requirement: header names collide case-insensitively on every platform.
        server = MCPServerDef(
            type="http",
            url="https://example.test/mcp",
            headers={"X-Token": "literal"},
            secrets=[_secret("alpha", "mcp", header="x-token")],
        )
        with pytest.raises(ConfigurationError, match=r"collides within consumer 'mcp:server'"):
            _validate_explicit(_mcp_config(server), _alpha_beta_environment(), tmp_path)

    def test_env_names_are_case_sensitive_off_windows(self, tmp_path: Path) -> None:
        # Requirement: env names collide only by exact case off Windows.
        config = _script_config(_secret("alpha", "script", env="token"), env={"TOKEN": "literal"})
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(os, "name", "posix")
            monkeypatch.setenv("CONDUCTOR_TEST_TASK10_ALPHA", "x")
            monkeypatch.setenv("CONDUCTOR_TEST_TASK10_BETA", "x")
            warnings = _validate_explicit(config, _alpha_beta_environment(), tmp_path)
        assert warnings == []

    def test_env_names_casefold_on_windows(self, tmp_path: Path) -> None:
        # Requirement: env names collide case-insensitively on Windows.
        config = _script_config(_secret("alpha", "script", env="token"), env={"TOKEN": "literal"})
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(os, "name", "nt")
            with pytest.raises(ConfigurationError, match="collides within consumer 'run'"):
                _validate_explicit(config, _alpha_beta_environment(), tmp_path)

    def test_distinct_delivery_names_are_clean(self, tmp_path: Path) -> None:
        # Requirement: distinct literal and delivery names produce no collision.
        config = _script_config(
            _secret("alpha", "script", env="TOKEN"),
            _secret("beta", "script", env="OTHER_TOKEN"),
            env={"LITERAL": "literal"},
        )
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv("CONDUCTOR_TEST_TASK10_ALPHA", "x")
            monkeypatch.setenv("CONDUCTOR_TEST_TASK10_BETA", "x")
            warnings = _validate_explicit(config, _alpha_beta_environment(), tmp_path)
        assert warnings == []


class TestExplicitEnvironment:
    """Explicit ``--environment`` makes environment checks authoritative."""

    def test_allow_violation_is_an_error_naming_the_allow_list(self, tmp_path: Path) -> None:
        # Requirement: a known ref consumed outside its allow list is an error
        # naming the allow list (the compiler checks only membership, not allow).
        environment = _environment({"token": _binding("CONDUCTOR_TEST_TASK10_TOKEN", ["mcp"])})
        config = _script_config(_secret("token", "script", env="TOKEN"))
        with pytest.raises(ConfigurationError, match=r"binding allow list is \[mcp\]"):
            _validate_explicit(config, environment, tmp_path)

    def test_allow_list_covering_the_scope_is_clean(self, tmp_path: Path) -> None:
        # Requirement: a consumer class present in the allow list passes.
        environment = _environment(
            {"token": _binding("CONDUCTOR_TEST_TASK10_TOKEN", ["script", "mcp"])}
        )
        config = _script_config(_secret("token", "script", env="TOKEN"))
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv("CONDUCTOR_TEST_TASK10_TOKEN", "x")
            warnings = _validate_explicit(config, environment, tmp_path)
        assert warnings == []

    def test_empty_allow_list_allows_no_consumer_classes(self, tmp_path: Path) -> None:
        # Requirement: ``allow: []`` is fail-closed and rejects every consumer.
        environment = _environment({"token": _binding("CONDUCTOR_TEST_TASK10_TOKEN", [])})
        config = _script_config(_secret("token", "script", env="TOKEN"))
        with pytest.raises(ConfigurationError, match=r"binding allow list is \[none\]"):
            _validate_explicit(config, environment, tmp_path)

    def test_unset_source_env_warns(self, tmp_path: Path) -> None:
        # Requirement: under --environment an unset source variable warns, because
        # the validation machine is not necessarily the run machine.
        environment = _environment({"token": _binding("CONDUCTOR_TEST_TASK10_UNSET")})
        config = _script_config(_secret("token", "script", env="TOKEN"))
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.delenv("CONDUCTOR_TEST_TASK10_UNSET", raising=False)
            warnings = _validate_explicit(config, environment, tmp_path)
        assert any(
            "secret binding 'token' uses an environment source that is unset" in w for w in warnings
        )

    def test_set_source_env_does_not_warn(self, tmp_path: Path) -> None:
        # Requirement: a present source variable produces no unset warning.
        environment = _environment({"token": _binding("CONDUCTOR_TEST_TASK10_SET")})
        config = _script_config(_secret("token", "script", env="TOKEN"))
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv("CONDUCTOR_TEST_TASK10_SET", "x")
            warnings = _validate_explicit(config, environment, tmp_path)
        assert warnings == []

    def test_unknown_ref_is_not_double_reported_by_the_validator(self, tmp_path: Path) -> None:
        # Requirement: under --environment, unknown refs surface through manifest
        # compilation (which runs first), so the validator stays silent on them.
        environment = _environment({"token": _binding("CONDUCTOR_TEST_TASK10_TOKEN")})
        config = _script_config(_secret("ghost", "script", env="TOKEN"))
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv("CONDUCTOR_TEST_TASK10_TOKEN", "x")
            warnings = _validate_explicit(config, environment, tmp_path)
        assert warnings == []

    def test_explicit_mode_never_discovers(self, tmp_path: Path) -> None:
        # Requirement: an explicit environment disables ambient discovery entirely.
        config = _script_config(_secret("alpha", "script", env="TOKEN"))
        with (
            patch("conductor.config.environment.discover_all_environments") as discover,
            pytest.MonkeyPatch.context() as monkeypatch,
        ):
            monkeypatch.setenv("CONDUCTOR_TEST_TASK10_ALPHA", "x")
            monkeypatch.setenv("CONDUCTOR_TEST_TASK10_BETA", "x")
            _validate_explicit(config, _alpha_beta_environment(), tmp_path)
        discover.assert_not_called()


class TestAmbientDiscovery:
    """Ambient (no --environment) three-level cross-check against authored envs."""

    def test_no_authored_environments_warns_and_never_errors(self, tmp_path: Path) -> None:
        # Requirement (Metis RISK-4): with zero authored environments the
        # built-in ``local/default`` never counts, so the check degrades to a
        # single warning pointing at ``--environment``.
        config = _script_config(_secret("alpha", "script", env="TOKEN"))
        with patch("conductor.config.environment.discover_all_environments", return_value={}):
            warnings = validate_workflow_config(config, workflow_path=tmp_path / "workflow.yaml")
        assert any(
            "could not be checked against any authored environment" in w
            and "conductor validate --environment" in w
            for w in warnings
        )

    def test_builtin_source_environment_never_counts_as_authored(self, tmp_path: Path) -> None:
        # Requirement (Metis RISK-4): even if discovery ever surfaced a
        # builtin-sourced document, it must not count toward the ambient check.
        builtin = ResolvedEnvironment(
            document=EnvironmentDocument(
                default="default",
                profiles={"default": ProfileDefinition(backend="local")},
            ),
            name="local/default",
            source="builtin",
            path=None,
            digest="sha256:builtin",
        )
        config = _script_config(_secret("alpha", "script", env="TOKEN"))
        with patch(
            "conductor.config.environment.discover_all_environments",
            return_value={"local/default": builtin},
        ):
            warnings = validate_workflow_config(config, workflow_path=tmp_path / "workflow.yaml")
        assert any("could not be checked against any authored environment" in w for w in warnings)
        assert not any("not defined in any discovered" in w for w in warnings)

    def test_ref_unknown_in_all_authored_environments_is_an_error(self, tmp_path: Path) -> None:
        # Requirement: a ref unknown to every authored environment is an error
        # naming all of them.
        environments = {
            "one": _environment({"token": _binding("CONDUCTOR_TEST_TASK10_ONE")}, name="one"),
            "two": _environment({"other": _binding("CONDUCTOR_TEST_TASK10_TWO")}, name="two"),
        }
        config = _script_config(_secret("alpha", "script", env="TOKEN"))
        with (
            patch(
                "conductor.config.environment.discover_all_environments",
                return_value=environments,
            ),
            pytest.raises(
                ConfigurationError, match=r"not defined in any discovered authored environment"
            ) as exc_info,
        ):
            validate_workflow_config(config, workflow_path=tmp_path / "workflow.yaml")
        assert "one" in str(exc_info.value) and "two" in str(exc_info.value)

    def test_ref_missing_from_some_environments_warns(self, tmp_path: Path) -> None:
        # Requirement: a ref known in only some authored environments warns,
        # naming just the ones missing it.
        environments = {
            "has-alpha": _environment(
                {"alpha": _binding("CONDUCTOR_TEST_TASK10_ALPHA")}, name="has-alpha"
            ),
            "missing-alpha": _environment(
                {"beta": _binding("CONDUCTOR_TEST_TASK10_BETA")}, name="missing-alpha"
            ),
        }
        config = _script_config(_secret("alpha", "script", env="TOKEN"))
        with patch(
            "conductor.config.environment.discover_all_environments",
            return_value=environments,
        ):
            warnings = validate_workflow_config(config, workflow_path=tmp_path / "workflow.yaml")
        absent = [w for w in warnings if "absent from environment(s)" in w]
        assert len(absent) == 1
        assert "missing-alpha" in absent[0]
        assert "has-alpha" not in absent[0]

    def test_ref_known_in_all_environments_is_clean(self, tmp_path: Path) -> None:
        # Requirement: a ref present in every authored environment is silent.
        environments = {
            "one": _environment({"alpha": _binding("CONDUCTOR_TEST_TASK10_ONE")}, name="one"),
            "two": _environment({"alpha": _binding("CONDUCTOR_TEST_TASK10_TWO")}, name="two"),
        }
        config = _script_config(_secret("alpha", "script", env="TOKEN"))
        with patch(
            "conductor.config.environment.discover_all_environments",
            return_value=environments,
        ):
            warnings = validate_workflow_config(config, workflow_path=tmp_path / "workflow.yaml")
        assert warnings == []

    def test_ambient_mode_never_checks_source_presence(self, tmp_path: Path) -> None:
        # Requirement: unset-source warnings fire only under --environment;
        # ambient validation never reads ``os.environ`` for secret sources.
        environments = {
            "one": _environment({"alpha": _binding("CONDUCTOR_TEST_TASK10_UNSET")}, name="one"),
        }
        config = _script_config(_secret("alpha", "script", env="TOKEN"))
        with (
            patch(
                "conductor.config.environment.discover_all_environments",
                return_value=environments,
            ),
            pytest.MonkeyPatch.context() as monkeypatch,
        ):
            monkeypatch.delenv("CONDUCTOR_TEST_TASK10_UNSET", raising=False)
            warnings = validate_workflow_config(config, workflow_path=tmp_path / "workflow.yaml")
        assert not any("unset" in w for w in warnings)

    def test_malformed_environment_counts_as_missing(self, tmp_path: Path) -> None:
        # Requirement: a malformed discovered document (``None`` entry) counts as
        # not providing the ref, mirroring the profile cross-check.
        environments = {
            "good": _environment({"alpha": _binding("CONDUCTOR_TEST_TASK10_ONE")}, name="good"),
            "broken": None,
        }
        config = _script_config(_secret("alpha", "script", env="TOKEN"))
        with patch(
            "conductor.config.environment.discover_all_environments",
            return_value=environments,
        ):
            warnings = validate_workflow_config(config, workflow_path=tmp_path / "workflow.yaml")
        absent = [w for w in warnings if "absent from environment(s)" in w]
        assert len(absent) == 1
        assert "broken" in absent[0]

    def test_no_secret_refs_never_discovers(self, tmp_path: Path) -> None:
        # Requirement: a secret-free workflow pays zero secret validation and
        # zero environment discovery I/O.
        config = WorkflowConfig(
            workflow=WorkflowDef(name="plain", entry_point="run"),
            agents=[ScriptStepDef(name="run", command="echo", routes=[RouteDef(to="$end")])],
            output={"result": "{{ run.output.stdout }}"},
        )
        with patch("conductor.config.environment.discover_all_environments") as discover:
            warnings = validate_workflow_config(config, workflow_path=tmp_path / "workflow.yaml")
        discover.assert_not_called()
        assert warnings == []

    def test_secret_validator_is_not_called_without_references(self, tmp_path: Path) -> None:
        # Requirement: the lazy gate in ``validate_workflow_config`` skips the
        # secret validator entirely for secret-free workflows.
        config = WorkflowConfig(
            workflow=WorkflowDef(name="plain", entry_point="run"),
            agents=[ScriptStepDef(name="run", command="echo", routes=[RouteDef(to="$end")])],
            output={"result": "{{ run.output.stdout }}"},
        )
        with patch("conductor.config.validator._validate_secret_references") as validator:
            validate_workflow_config(config, workflow_path=tmp_path / "workflow.yaml")
        validator.assert_not_called()

    def test_profile_and_secret_refs_share_one_discovery(self, tmp_path: Path) -> None:
        # Requirement: profile and secret cross-checks share the context's single
        # lazy discovery scan.
        config = WorkflowConfig(
            workflow=WorkflowDef(
                name="both",
                entry_point="run",
                defaults=WorkflowDefaults(execution=StepExecutionConfig(profile="shell")),
            ),
            agents=[
                ScriptStepDef(
                    name="run",
                    command="echo",
                    execution=StepExecutionConfig(secrets=[_secret("alpha", "script", env="T")]),
                    routes=[RouteDef(to="$end")],
                )
            ],
            output={"result": "{{ run.output.stdout }}"},
        )
        with patch(
            "conductor.config.environment.discover_all_environments", return_value={}
        ) as discover:
            warnings = validate_workflow_config(config, workflow_path=tmp_path / "workflow.yaml")
        discover.assert_called_once_with(tmp_path, on_warning=ANY)
        assert any("profile references could not be checked" in w for w in warnings)
        assert any("secret references could not be checked" in w for w in warnings)
