"""Tests for the ``execution:`` schema surface (execution profiles feature).

Covers:
- ``StepExecutionConfig``: ``profile`` charset, whitespace handling, extra-key forbid.
- ``execution:`` parses on the four executable step types (agent, script, mcp, workflow).
- ``execution:`` is rejected on engine-local step types (set, wait, terminate,
  human_gate, questions) via their existing ``extra="forbid"`` — a negative
  control proving the field did not leak through a common base class.
- ``WorkflowDef.defaults.execution`` parses and defaults; extra keys are forbidden.
- An untagged agent with ``execution:`` still normalizes through the ``StepDef`` union.
"""

from __future__ import annotations

import pytest
from pydantic import TypeAdapter, ValidationError

from conductor.config.loader import load_config_string
from conductor.config.schema import (
    AgentDef,
    MCPStepDef,
    ScriptStepDef,
    StepDef,
    StepExecutionConfig,
    WorkflowConfig,
    WorkflowDefaults,
    WorkflowStepDef,
)
from conductor.exceptions import ConfigurationError


class TestStepExecutionConfig:
    """Field shape, charset, and ``extra="forbid"`` for the step-level block."""

    def test_defaults(self) -> None:
        # Requirement: an absent ``execution:`` block is equivalent to an empty one.
        config = StepExecutionConfig()
        assert config.profile is None

    def test_profile_round_trip(self) -> None:
        # Requirement: a valid profile name parses and is stored verbatim.
        config = StepExecutionConfig(profile="shell")
        assert config.profile == "shell"

    @pytest.mark.parametrize(
        "profile",
        ["local", "docker.sandbox", "gpu-cluster_2", "A" * 64],
    )
    def test_profile_charset_accepts_valid_names(self, profile: str) -> None:
        # Requirement: [A-Za-z0-9_.-]+ names parse, including dots, dashes, and underscores.
        config = StepExecutionConfig(profile=profile)
        assert config.profile == profile

    @pytest.mark.parametrize(
        "profile",
        ["bad name!", "with/slash", "with\\backslash", "with:colon", "with space"],
    )
    def test_profile_charset(self, profile: str) -> None:
        # Requirement: a name outside [A-Za-z0-9_.-] fails with an error naming the charset.
        with pytest.raises(ValidationError, match=r"\[A-Za-z0-9_.-\]\+"):
            StepExecutionConfig(profile=profile)

    def test_profile_rejects_empty_and_blank(self) -> None:
        # Requirement: a profile that is empty after stripping is rejected.
        with pytest.raises(ValidationError):
            StepExecutionConfig(profile="   ")

    def test_profile_strips_surrounding_whitespace(self) -> None:
        # Requirement: surrounding whitespace is normalized before the charset check.
        config = StepExecutionConfig(profile="  shell  ")
        assert config.profile == "shell"

    def test_extra_key_forbidden(self) -> None:
        # Requirement: a typo inside the block is a schema error, not silently ignored.
        with pytest.raises(ValidationError, match="(?i)extra inputs are not permitted"):
            StepExecutionConfig(profil="shell")  # type: ignore[call-arg]


class TestExecutableSteps:
    """``execution:`` parses on agent, script, mcp, and workflow steps."""

    def test_agent_step_accepts_execution(self) -> None:
        # Requirement: an LLM agent step may declare an execution profile.
        config = load_config_string(
            """
workflow:
  name: profiled
  entry_point: writer
agents:
  - name: writer
    execution:
      profile: shell
    prompt: "Write"
"""
        )

        agent = config.agents[0]
        assert isinstance(agent, AgentDef)
        assert agent.execution is not None
        assert agent.execution.profile == "shell"

    def test_script_step_accepts_execution(self) -> None:
        # Requirement: a script step may declare an execution profile.
        config = load_config_string(
            """
workflow:
  name: profiled
  entry_point: probe
agents:
  - name: probe
    type: script
    execution:
      profile: shell
    command: echo
    args: ["ok"]
"""
        )

        step = config.agents[0]
        assert isinstance(step, ScriptStepDef)
        assert step.execution is not None
        assert step.execution.profile == "shell"

    def test_mcp_step_accepts_execution(self) -> None:
        # Requirement: a direct MCP tool-call step may declare an execution profile.
        config = load_config_string(
            """
workflow:
  name: profiled
  entry_point: caller
agents:
  - name: caller
    type: mcp
    execution:
      profile: shell
    server: filesystem
    tool: read_file
"""
        )

        step = config.agents[0]
        assert isinstance(step, MCPStepDef)
        assert step.execution is not None
        assert step.execution.profile == "shell"

    def test_workflow_step_accepts_execution(self) -> None:
        # Requirement: a nested-workflow step may declare an execution profile.
        config = load_config_string(
            """
workflow:
  name: profiled
  entry_point: nested
agents:
  - name: nested
    type: workflow
    execution:
      profile: shell
    workflow: ./child.yaml
"""
        )

        step = config.agents[0]
        assert isinstance(step, WorkflowStepDef)
        assert step.execution is not None
        assert step.execution.profile == "shell"

    def test_step_without_execution_defaults_to_none(self) -> None:
        # Requirement: steps omitting the block keep ``execution is None`` (no behavior change).
        config = load_config_string(
            """
workflow:
  name: plain
  entry_point: probe
agents:
  - name: probe
    type: script
    command: echo
"""
        )

        step = config.agents[0]
        assert isinstance(step, ScriptStepDef)
        assert step.execution is None


class TestEngineLocalRejection:
    """``execution:`` is refused on engine-local steps by their ``extra="forbid"``.

    Negative control: these step types must NOT inherit the field, so the
    error path is their own extra-key rejection and the error location points
    at the ``execution`` key.
    """

    @pytest.mark.parametrize(
        "step_type,extra_yaml",
        [
            ("set", '    value: "1"\n'),
            ("wait", "    duration: 1s\n"),
            ("terminate", '    status: success\n    reason: "done"\n'),
            (
                "human_gate",
                '    prompt: "Approve?"\n    options:\n      - label: "yes"\n',
            ),
            ("questions", '    questions:\n      - prompt: "Which?"\n'),
        ],
    )
    def test_execution_rejected_on_engine_local_steps(
        self, step_type: str, extra_yaml: str
    ) -> None:
        # Requirement: engine-local steps reject ``execution:`` as an extra input,
        # proving the field did not leak through a shared base class.
        yaml_text = (
            "workflow:\n"
            "  name: local\n"
            "  entry_point: step\n"
            "agents:\n"
            "  - name: step\n"
            f"    type: {step_type}\n"
            "    execution:\n"
            "      profile: shell\n" + extra_yaml
        )

        # The loader wraps schema errors in ConfigurationError; its message
        # keeps the error path, so "execution" must appear there.
        with pytest.raises(ConfigurationError, match=r"execution"):
            load_config_string(yaml_text)


class TestWorkflowDefaults:
    """``workflow.defaults.execution`` parses, defaults, and forbids extras."""

    def test_defaults_execution_parses(self) -> None:
        # Requirement: a workflow-level default execution profile applies to the workflow block.
        config = load_config_string(
            """
workflow:
  name: defaulted
  entry_point: probe
  defaults:
    execution:
      profile: shell
agents:
  - name: probe
    type: script
    command: echo
"""
        )

        assert config.workflow.defaults.execution is not None
        assert config.workflow.defaults.execution.profile == "shell"

    def test_absent_defaults_block_equals_default_instance(self) -> None:
        # Requirement: an absent ``defaults:`` block is identical to an explicit empty one.
        without = load_config_string(
            """
workflow:
  name: plain
  entry_point: probe
agents:
  - name: probe
    type: script
    command: echo
"""
        )
        assert without.workflow.defaults == WorkflowDefaults()

    def test_extra_key_forbidden(self) -> None:
        # Requirement: a typo inside ``workflow.defaults`` is a schema error, not ignored.
        with pytest.raises(ValidationError, match="(?i)extra inputs are not permitted"):
            WorkflowDefaults(retries=3)  # type: ignore[call-arg]

    def test_execution_extra_key_forbidden(self) -> None:
        # Requirement: a typo inside ``defaults.execution`` is a schema error as well.
        with pytest.raises(ValidationError, match="(?i)extra inputs are not permitted"):
            WorkflowDefaults(execution={"profil": "shell"})  # type: ignore[arg-type]


class TestUnionNormalization:
    """The ``StepDef`` union keeps routing untagged agents with ``execution:``."""

    def test_untagged_agent_with_execution_normalizes_through_union(self) -> None:
        # Requirement: an untagged LLM agent carrying ``execution:`` still parses
        # as ``AgentDef`` via the union's before-validator.
        adapter = TypeAdapter(StepDef)
        step = adapter.validate_python(
            {"name": "writer", "prompt": "Write", "execution": {"profile": "shell"}}
        )

        assert type(step) is AgentDef
        assert step.execution is not None
        assert step.execution.profile == "shell"

    def test_engine_local_variant_schemas_do_not_offer_execution(self) -> None:
        # Requirement: the published JSON Schema exposes ``execution`` only on
        # executable variants, not on engine-local ones.
        schema = WorkflowConfig.model_json_schema()
        defs = schema["$defs"]

        for variant in ("AgentDef", "ScriptStepDef", "MCPStepDef", "WorkflowStepDef"):
            assert "execution" in defs[variant]["properties"], variant
        for variant in (
            "SetStepDef",
            "WaitStepDef",
            "TerminateStepDef",
            "HumanGateStepDef",
            "QuestionsStepDef",
        ):
            assert "execution" not in defs[variant]["properties"], variant
