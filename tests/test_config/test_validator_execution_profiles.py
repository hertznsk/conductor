"""Tests for execution profile validation context and discovery rules."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast
from unittest.mock import ANY, patch

from conductor.config.schema import (
    AgentDef,
    RouteDef,
    StepExecutionConfig,
    WorkflowConfig,
    WorkflowDef,
    WorkflowDefaults,
    WorkflowStepDef,
)
from conductor.config.validator import validate_workflow_config


class TestExecutionProfileValidationContext:
    """Requirements for recursive lazy execution-profile validation."""

    def test_recursive_profile_refs_share_one_root_discovery(self, tmp_path: Path) -> None:
        # Requirement: a profile ref first encountered in a child triggers one
        # discovery anchored at the root workflow directory.
        root_path = tmp_path / "root.yaml"
        child_path = tmp_path / "nested" / "child.yaml"
        child_path.parent.mkdir()
        child_path.write_text(
            """\
workflow:
  name: child
  entry_point: work
  defaults:
    execution:
      profile: shell
agents:
  - name: work
    prompt: work
    routes:
      - to: $end
""",
            encoding="utf-8",
        )
        root_path.write_text(
            """\
workflow:
  name: root
  entry_point: child
agents:
  - name: child
    type: workflow
    workflow: nested/child.yaml
    routes:
      - to: $end
""",
            encoding="utf-8",
        )
        config = WorkflowConfig(
            workflow=WorkflowDef(name="root", entry_point="child"),
            agents=[
                WorkflowStepDef(
                    name="child",
                    workflow="nested/child.yaml",
                    routes=[RouteDef(to="$end")],
                )
            ],
        )

        with patch(
            "conductor.config.environment.discover_all_environments",
            return_value={},
        ) as discover:
            warnings = validate_workflow_config(config, workflow_path=root_path)

        discover.assert_called_once_with(tmp_path, on_warning=ANY)
        assert any("could not be checked against any environment" in item for item in warnings)

    def test_explicit_context_skips_bare_discovery(self, tmp_path: Path) -> None:
        # Requirement: explicit --environment validation disables the ambient
        # cross-check even when authored profile references exist.
        config = WorkflowConfig(
            workflow=WorkflowDef(
                name="explicit",
                entry_point="worker",
                defaults=WorkflowDefaults(execution=StepExecutionConfig(profile="shell")),
            ),
            agents=[AgentDef(name="worker", prompt="work", routes=[RouteDef(to="$end")])],
        )
        context = {
            "refs_found": False,
            "environments": None,
            "explicit": True,
            "root_workflow_dir": tmp_path,
            "warned_no_environments": False,
        }

        with patch("conductor.config.environment.discover_all_environments") as discover:
            warnings = validate_workflow_config(
                config,
                workflow_path=tmp_path / "workflow.yaml",
                _environment_context=cast(Any, context),
            )

        discover.assert_not_called()
        assert warnings == []

    def test_root_and_child_refs_with_no_environments_warn_only_once(self, tmp_path: Path) -> None:
        # Requirement: when no environments are discoverable, profile refs in
        # both root and child workflows remain unchecked and produce one warning.
        root_path = tmp_path / "root.yaml"
        child_path = tmp_path / "child.yaml"
        child_path.write_text(
            """\
workflow:
  name: child
  entry_point: work
  defaults:
    execution:
      profile: child-profile
agents:
  - name: work
    prompt: work
    routes:
      - to: $end
""",
            encoding="utf-8",
        )
        config = WorkflowConfig(
            workflow=WorkflowDef(
                name="root",
                entry_point="child",
                defaults=WorkflowDefaults(execution=StepExecutionConfig(profile="root-profile")),
            ),
            agents=[
                WorkflowStepDef(
                    name="child",
                    workflow="child.yaml",
                    routes=[RouteDef(to="$end")],
                )
            ],
        )

        with patch(
            "conductor.config.environment.discover_all_environments",
            return_value={},
        ) as discover:
            warnings = validate_workflow_config(config, workflow_path=root_path)

        discover.assert_called_once_with(tmp_path, on_warning=ANY)
        unchecked = [
            warning
            for warning in warnings
            if "profile references could not be checked against any environment" in warning
        ]
        assert len(unchecked) == 1
        assert not any(
            "not defined in any discovered environment" in warning for warning in warnings
        )
