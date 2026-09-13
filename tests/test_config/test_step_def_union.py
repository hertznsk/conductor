"""Regression coverage for the static ``StepDef`` discriminated union (issue #517).

Covers the boundaries the per-variant schema test files do not: the published
JSON Schema shape, ``ForEachDef.agent`` parsing, serialization round-trips,
and legacy ``type`` shorthand canonicalization.
"""

from __future__ import annotations

import pytest
from pydantic import TypeAdapter
from pydantic import ValidationError as PydanticValidationError

from conductor.config.loader import load_config_string
from conductor.config.schema import (
    AgentDef,
    ForEachDef,
    HumanGateStepDef,
    MCPStepDef,
    QuestionsStepDef,
    ScriptStepDef,
    SetStepDef,
    StepDef,
    TerminateStepDef,
    WaitStepDef,
    WorkflowConfig,
    WorkflowStepDef,
)

_STEP_CLASSES = (
    AgentDef,
    HumanGateStepDef,
    QuestionsStepDef,
    ScriptStepDef,
    MCPStepDef,
    WaitStepDef,
    SetStepDef,
    TerminateStepDef,
    WorkflowStepDef,
)

_STEP_TAGS = {
    "agent",
    "human_gate",
    "questions",
    "script",
    "mcp",
    "wait",
    "set",
    "terminate",
    "workflow",
}


def _workflow_payload(agents: list[dict]) -> dict:
    return {
        "workflow": {"name": "typed", "entry_point": agents[0]["name"]},
        "agents": agents,
    }


class TestJsonSchemaShape:
    """The published JSON Schema must expose the union, not the old monolith."""

    def test_agents_items_use_one_of_with_discriminator(self) -> None:
        # Requirement: schema consumers select a variant via discriminator metadata.
        items = WorkflowConfig.model_json_schema()["properties"]["agents"]["items"]

        assert len(items["oneOf"]) == 9
        discriminator = items["discriminator"]
        assert discriminator["propertyName"] == "type"
        assert set(discriminator["mapping"]) == _STEP_TAGS

    def test_discriminator_mapping_points_at_named_variants(self) -> None:
        # Requirement: every tag maps to the $def of its concrete step model.
        schema = WorkflowConfig.model_json_schema()
        mapping = schema["properties"]["agents"]["items"]["discriminator"]["mapping"]

        for ref in mapping.values():
            assert ref.startswith("#/$defs/")
            assert ref.removeprefix("#/$defs/") in schema["$defs"]

    def test_every_variant_def_forbids_additional_properties(self) -> None:
        # Requirement: variant-local fields are enforced in the published schema.
        schema = WorkflowConfig.model_json_schema()
        mapping = schema["properties"]["agents"]["items"]["discriminator"]["mapping"]

        for ref in mapping.values():
            variant_schema = schema["$defs"][ref.removeprefix("#/$defs/")]
            assert variant_schema["additionalProperties"] is False

    def test_terminate_def_has_no_routes(self) -> None:
        # Requirement: terminate steps cannot route; the schema must not offer it.
        schema = WorkflowConfig.model_json_schema()
        terminate_schema = schema["$defs"]["TerminateStepDef"]

        assert "routes" not in terminate_schema["properties"]

    def test_for_each_agent_uses_same_union(self) -> None:
        # Requirement: ForEachDef.agent parses through the identical StepDef union.
        schema = WorkflowConfig.model_json_schema()
        for_each_agent = schema["$defs"]["ForEachDef"]["properties"]["agent"]

        assert len(for_each_agent["oneOf"]) == 9
        assert for_each_agent["discriminator"]["propertyName"] == "type"


class TestForEachAgentParsing:
    """``ForEachDef.agent`` accepts the executable inline variants."""

    @pytest.mark.parametrize(
        ("agent_payload", "expected_class"),
        [
            ({"name": "w", "prompt": "Do {{ item }}"}, AgentDef),
            ({"name": "w", "type": "workflow", "workflow": "./sub.yaml"}, WorkflowStepDef),
            ({"name": "w", "type": "set", "value": "{{ item }}"}, SetStepDef),
            (
                {"name": "w", "type": "mcp", "server": "docs", "tool": "search"},
                MCPStepDef,
            ),
        ],
        ids=["agent", "workflow", "set", "mcp"],
    )
    def test_inline_variants_parse(self, agent_payload: dict, expected_class: type) -> None:
        # Requirement: for-each inline agents keep working for every supported kind.
        group = ForEachDef.model_validate(
            {
                "name": "loop",
                "type": "for_each",
                "source": "finder.output.items",
                "as": "item",
                "agent": agent_payload,
            }
        )

        assert type(group.agent) is expected_class

    def test_inline_agent_without_type_is_llm(self) -> None:
        # Requirement: an inline agent omitting ``type`` is a provider-backed agent.
        group = ForEachDef.model_validate(
            {
                "name": "loop",
                "type": "for_each",
                "source": "finder.output.items",
                "as": "item",
                "agent": {"name": "w", "prompt": "Do {{ item }}"},
            }
        )

        assert isinstance(group.agent, AgentDef)
        assert group.agent.type == "agent"


class TestLegacyTypeCanonicalization:
    """Omitted and explicit-null ``type`` remain valid shorthands for LLM agents."""

    def test_yaml_without_type_loads_as_agent(self) -> None:
        # Requirement: pre-#517 YAML with no ``type`` keeps loading, canonicalized.
        config = load_config_string(
            """
workflow:
  name: legacy
  entry_point: write
agents:
  - name: write
    prompt: "Write"
"""
        )

        assert type(config.agents[0]) is AgentDef
        assert config.agents[0].type == "agent"

    def test_yaml_with_null_type_loads_as_agent(self) -> None:
        # Requirement: an explicit ``type: null`` stays compatible, canonicalized.
        config = load_config_string(
            """
workflow:
  name: legacy
  entry_point: write
agents:
  - name: write
    type: null
    prompt: "Write"
"""
        )

        assert type(config.agents[0]) is AgentDef
        assert config.agents[0].type == "agent"

    def test_direct_constructor_accepts_none_type(self) -> None:
        # Requirement: programmatic ``AgentDef(type=None)`` keeps working.
        agent = AgentDef(name="write", type=None, prompt="Write")  # type: ignore[arg-type]

        assert agent.type == "agent"

    def test_step_adapter_normalizes_null_type(self) -> None:
        # Requirement: the shared StepDef boundary applies the same normalization.
        step = TypeAdapter(StepDef).validate_python({"name": "write", "type": None})

        assert type(step) is AgentDef
        assert step.type == "agent"

    def test_unknown_type_is_union_tag_invalid(self) -> None:
        # Requirement: an unrecognized discriminator is a schema error, not a guess.
        with pytest.raises(PydanticValidationError) as exc_info:
            WorkflowConfig.model_validate(
                _workflow_payload([{"name": "x", "type": "bogus"}])
            )

        assert any(e["type"] == "union_tag_invalid" for e in exc_info.value.errors())


class TestSerializationRoundTrip:
    """``model_dump(exclude_none=True)`` of each variant revalidates identically."""

    @pytest.mark.parametrize(
        "step",
        [
            AgentDef(name="write", prompt="Write"),
            HumanGateStepDef(
                name="gate",
                prompt="Pick",
                options=[{"label": "Yes", "value": "yes", "route": "$end"}],
            ),
            QuestionsStepDef(
                name="ask", questions=[{"id": "q1", "text": "Why?"}]
            ),
            ScriptStepDef(name="run", command="echo hi"),
            MCPStepDef(name="call", server="docs", tool="search"),
            WaitStepDef(name="pause", duration="1s"),
            SetStepDef(name="bind", value="1"),
            TerminateStepDef(name="stop", status="success", reason="done"),
            WorkflowStepDef(name="child", workflow="./sub.yaml"),
        ],
        ids=lambda step: step.type,
    )
    def test_dump_revalidates_through_workflow_config(self, step: StepDef) -> None:
        # Requirement: serialized steps round-trip through the union boundary.
        dumped = step.model_dump(exclude_none=True)
        config = WorkflowConfig.model_validate(
            {
                "workflow": {"name": "rt", "entry_point": step.name},
                "agents": [dumped],
            }
        )

        assert type(config.agents[0]) is type(step)
        assert config.agents[0].type == step.type

    def test_llm_dump_carries_canonical_type(self) -> None:
        # Requirement: the canonical discriminator survives serialization.
        dumped = AgentDef(name="write", prompt="Write").model_dump(exclude_none=True)

        assert dumped["type"] == "agent"
