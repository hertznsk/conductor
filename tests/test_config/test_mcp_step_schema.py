"""Tests for ``type: mcp`` step schema validation.

Tests cover:
- Valid mcp agent definitions (minimal + full)
- Required server/tool validation
- The full forbidden-field matrix (every LLM and sibling-step field)
- Literal-only server/tool (Jinja templates rejected at load time)
- timeout acceptance (unlike wait/set steps)
- server/tool/arguments rejection on all other step types

Field matrix under test (requirement: every AgentDef field must be
allow / forbid / covered-by-standalone-guard for ``type: mcp``):
- ALLOWED: name, description, input, output, routes, timeout, server, tool,
  arguments
- FORBIDDEN: prompt, system_prompt, provider, model, tools, reasoning,
  context_tier, skills, plugins, validator, dialog, sandbox, session_key,
  max_agent_iterations, max_session_seconds, output_mode, retry,
  timeout_seconds, command, args, env, working_dir, options, workflow,
  input_mapping, max_depth, value, values, output_type
- COVERED BY STANDALONE GUARDS: stdin (script guard), duration + reason
  (wait/terminate guard), status + output_template (terminate guard),
  questions/source/allow_*/abort_route (questions guard), server/tool/
  arguments on non-mcp types (mcp-exclusive guard)
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from conductor.config.schema import AgentDef, GateOption, OutputField, RouteDef


def _mcp_agent(**overrides: Any) -> AgentDef:
    """Build a valid minimal mcp agent, applying overrides."""
    kwargs: dict[str, Any] = {"name": "lookup", "type": "mcp", "server": "docs", "tool": "search"}
    kwargs.update(overrides)
    return AgentDef(**kwargs)


class TestMcpAgentDefValid:
    """Tests for valid mcp type AgentDef construction."""

    def test_valid_minimal_mcp_step(self) -> None:
        """Requirement: a minimal type: mcp step needs only server and tool."""
        agent = _mcp_agent()
        assert agent.type == "mcp"
        assert agent.server == "docs"
        assert agent.tool == "search"
        assert agent.arguments is None
        assert agent.timeout is None

    def test_valid_mcp_step_with_all_allowed_fields(self) -> None:
        """Requirement: output, routes, input, timeout, description, arguments are allowed."""
        agent = _mcp_agent(
            description="Look up docs",
            arguments={"query": "{{ workflow.input.q }}"},
            input=["prep.output"],
            output={"hits": OutputField(type="number")},
            routes=[RouteDef(to="$end")],
            timeout=30,
        )
        assert agent.arguments == {"query": "{{ workflow.input.q }}"}
        assert agent.timeout == 30
        assert "hits" in (agent.output or {})

    def test_mcp_step_timeout_accepted(self) -> None:
        """Requirement: timeout is allowed on mcp steps (unlike wait/set which forbid it)."""
        agent = _mcp_agent(timeout=30)
        assert agent.timeout == 30

    def test_mcp_step_output_accepted(self) -> None:
        """Requirement: mcp steps may declare an output schema like script steps."""
        agent = _mcp_agent(output={"result": OutputField(type="string")})
        assert agent.output is not None

    def test_mcp_arguments_allow_jinja_templates(self) -> None:
        """Requirement: arguments ARE rendered recursively, so Jinja is allowed there."""
        agent = _mcp_agent(arguments={"q": "{{ searcher.output.query }}", "n": 5})
        assert agent.arguments == {"q": "{{ searcher.output.query }}", "n": 5}


class TestMcpAgentDefRequiredFields:
    """Tests for required server/tool fields."""

    def test_mcp_without_server_raises(self) -> None:
        """Requirement: mcp steps require 'server'."""
        with pytest.raises(ValidationError, match="mcp agents require 'server'"):
            AgentDef(name="bad", type="mcp", tool="search")

    def test_mcp_with_empty_server_raises(self) -> None:
        """Requirement: an empty server string is rejected as missing."""
        with pytest.raises(ValidationError, match="mcp agents require 'server'"):
            AgentDef(name="bad", type="mcp", server="", tool="search")

    def test_mcp_without_tool_raises(self) -> None:
        """Requirement: mcp steps require 'tool'."""
        with pytest.raises(ValidationError, match="mcp agents require 'tool'"):
            AgentDef(name="bad", type="mcp", server="docs")

    def test_mcp_with_empty_tool_raises(self) -> None:
        """Requirement: an empty tool string is rejected as missing."""
        with pytest.raises(ValidationError, match="mcp agents require 'tool'"):
            AgentDef(name="bad", type="mcp", server="docs", tool="")


# Requirement: each LLM-only or sibling-step field must be rejected on mcp steps.
# field name -> (kwarg value, regex fragment matching the error message).
_FORBIDDEN_FIELDS: list[tuple[str, Any, str]] = [
    # LLM fields
    ("prompt", "do something", r"'prompt'"),
    ("system_prompt", "You are...", r"'system_prompt'"),
    ("provider", "copilot", r"'provider'"),
    ("model", "gpt-4", r"'model'"),
    ("tools", ["web_search"], r"'tools'"),
    ("reasoning", {"effort": "high"}, r"'reasoning'"),
    ("context_tier", "long_context", r"'context_tier'"),
    ("skills", ["conductor"], r"'skills'"),
    ("plugins", ["prs"], r"'plugins'"),
    ("validator", {"criteria": "must be good"}, r"'validator'"),
    ("dialog", {"trigger_prompt": "pause if unsure"}, r"'dialog'"),
    ("sandbox", {"identifier_scope": "item"}, r"'sandbox'"),
    ("session_key", "my-key", r"'session_key'"),
    ("max_agent_iterations", 5, r"'max_agent_iterations'"),
    ("max_session_seconds", 60.0, r"'max_session_seconds'"),
    ("output_mode", "raw", r"'output_mode'"),
    ("retry", {"max_attempts": 2}, r"'retry'"),
    (
        "timeout_seconds",
        30.0,
        r"'timeout_seconds'.*use 'timeout'",
    ),  # mirrors the script branch message
    # Sibling-step fields
    ("command", "echo", r"'command'"),
    ("args", ["a"], r"'args'"),
    ("env", {"A": "b"}, r"'env'"),
    ("working_dir", "/tmp", r"'working_dir'"),
    ("settings_dir", "/tmp", r"'settings_dir'"),
    ("options", [GateOption(label="OK", value="ok", route="$end")], r"'options'"),
    ("workflow", "sub.yaml", r"'workflow'"),
    ("input_mapping", {"a": "{{ b }}"}, r"'input_mapping'"),
    ("max_depth", 2, r"'max_depth'"),
    ("value", "{{ 1 }}", r"'value'"),
    ("values", {"a": "{{ 1 }}"}, r"'values'"),
    ("output_type", "auto", r"'output_type'"),
]


class TestMcpAgentDefForbiddenFields:
    """Parameterized matrix: every forbidden field is rejected with a named error."""

    @pytest.mark.parametrize(("field_name", "value", "message"), _FORBIDDEN_FIELDS)
    def test_mcp_forbidden_field_raises(self, field_name: str, value: Any, message: str) -> None:
        """Requirement: mcp steps cannot set LLM-only or sibling-step fields."""
        with pytest.raises(ValidationError, match=message):
            _mcp_agent(**{field_name: value})

    def test_mcp_with_stdin_raises(self) -> None:
        """Requirement: stdin is rejected via the standalone script guard."""
        with pytest.raises(ValidationError, match="'stdin'"):
            _mcp_agent(stdin="payload")

    def test_mcp_with_duration_raises(self) -> None:
        """Requirement: duration is rejected via the wait-only guard at method bottom."""
        with pytest.raises(ValidationError, match="'duration'"):
            _mcp_agent(duration=5)

    def test_mcp_with_reason_raises(self) -> None:
        """Requirement: reason is rejected (only wait/terminate support it)."""
        with pytest.raises(ValidationError, match="'reason'"):
            _mcp_agent(reason="because")

    def test_mcp_with_status_raises(self) -> None:
        """Requirement: status is rejected via the terminate-exclusive guard."""
        with pytest.raises(ValidationError, match="'status'"):
            _mcp_agent(status="success")

    def test_mcp_with_output_template_raises(self) -> None:
        """Requirement: output_template is rejected via the terminate-exclusive guard."""
        with pytest.raises(ValidationError, match="'output_template'"):
            _mcp_agent(output_template={"a": "b"})


class TestMcpFieldsLiteralOnly:
    """Tests for the literal-only server/tool contract."""

    @pytest.mark.parametrize(
        "template", ["{{ workflow.input.server }}", "{% if x %}docs{% endif %}"]
    )
    def test_jinja_in_server_rejected(self, template: str) -> None:
        """Requirement: server is never rendered — Jinja templates are rejected at load time."""
        with pytest.raises(ValidationError, match="never rendered"):
            AgentDef(name="bad", type="mcp", server=template, tool="search")

    @pytest.mark.parametrize(
        "template", ["{{ workflow.input.tool }}", "{% if x %}search{% endif %}"]
    )
    def test_jinja_in_tool_rejected(self, template: str) -> None:
        """Requirement: tool is never rendered — Jinja templates are rejected at load time."""
        with pytest.raises(ValidationError, match="never rendered"):
            AgentDef(name="bad", type="mcp", server="docs", tool=template)


class TestMcpFieldsForbiddenOnOtherTypes:
    """server/tool/arguments are exclusive to type: mcp."""

    @pytest.mark.parametrize("field_name", ["server", "tool", "arguments"])
    def test_mcp_fields_rejected_on_script(self, field_name: str) -> None:
        """Requirement: server/tool/arguments on a script step raise the mcp-exclusive error."""
        value: Any = {"server": "docs", "tool": "search"}.get(field_name, {"q": "x"})
        with pytest.raises(ValidationError, match=f"cannot have '{field_name}'"):
            AgentDef(name="bad", type="script", command="echo", **{field_name: value})

    @pytest.mark.parametrize("field_name", ["server", "tool", "arguments"])
    def test_mcp_fields_rejected_on_regular_agent(self, field_name: str) -> None:
        """Requirement: server/tool/arguments on an LLM agent raise the mcp-exclusive error."""
        value: Any = {"server": "docs", "tool": "search"}.get(field_name, {"q": "x"})
        with pytest.raises(ValidationError, match=f"cannot have '{field_name}'"):
            AgentDef(name="bad", prompt="hello", **{field_name: value})

    def test_mcp_fields_rejected_on_wait(self) -> None:
        """Requirement: server on a wait step is rejected even though wait has its own branch."""
        with pytest.raises(ValidationError, match="cannot have 'server'"):
            AgentDef(name="bad", type="wait", duration=5, server="docs")
