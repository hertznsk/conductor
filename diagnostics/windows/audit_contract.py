"""Consistency of structured receipts, separate from filesystem publication."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, TypedDict

from artifact_policy import MANDATORY_RECORDS, SCHEMA, Record
from artifact_snapshot import Parsed


class Timeline(TypedDict):
    status: Literal["unknown", "observed", "right-censored"]
    observations: list[Record]


@dataclass(frozen=True, slots=True)
class Assessment:
    structured_complete: bool
    lifecycle_complete: bool
    root: Record
    provenance: Record
    timeline: dict[str, Timeline]
    expected_roles: frozenset[str]
    missing_roles: frozenset[str]


def assess(summaries: Mapping[str, Parsed], phase_paths: Sequence[str]) -> Assessment:
    complete = True
    supervisor = summaries.get("supervisor.jsonl", Parsed())
    expected_run = next((r for r in supervisor.kept if r["event"] == "expected"), {})
    complete = expected_run.get("policy") == SCHEMA
    complete = complete and expected_run.get("expected_files") == list(MANDATORY_RECORDS)
    complete = complete and {"host", "process"}.issubset(
        summaries.get("processes.jsonl", Parsed()).events
    )
    complete = complete and not any(summary.producer_incomplete for summary in summaries.values())
    root = {**supervisor.last, "root_code": supervisor.last.get("root_code")}
    expected_workers = expected_run.get("workers", 0)
    phase_roles = {
        role
        for p in phase_paths
        if p in summaries and isinstance(role := summaries[p].first.get("worker"), str)
    }
    if not isinstance(expected_workers, int) or expected_workers not in (1, 2):
        expected_workers = 0
        complete = False
    if not {"controller", *(f"gw{i}" for i in range(expected_workers))}.issubset(phase_roles):
        complete = False
    for phase in phase_paths:
        summary = summaries.get(phase, Parsed())
        if not {"start", "stack-arm", "sessionfinish.end", "unconfigure.end"}.issubset(
            summary.events
        ):
            complete = False
        if summary.collected and summary.first.get("worker") == "controller":
            complete = complete and summary.calls == summary.collected
        for declared in (record["collected"] for record in summary.kept if "collected" in record):
            complete = complete and declared == summary.collected
    workers = [
        summaries[name]
        for name in phase_paths
        if name in summaries and summaries[name].first.get("worker") != "controller"
    ]
    controller = next(
        (
            summaries[name]
            for name in phase_paths
            if name in summaries and summaries[name].first.get("worker") == "controller"
        ),
        Parsed(),
    )
    selected = {worker.collected for worker in workers}
    if root.get("root_code") in (0, 1):
        complete = complete and len(selected) == 1
        complete = complete and len(controller.finished) in selected
    post_summary = summaries.get("post-root.jsonl", Parsed())
    post = post_summary.last
    lifecycle = post.get("event") == "post.end" and post.get("complete") is True
    lifecycle = lifecycle and post_summary.first.get("known") == len(post_summary.identities)
    physical = list(post_summary.physical.values())
    physical_roles = {role for record in physical if isinstance(role := record.get("role"), str)}
    required_roles = {"controller", *(f"gw{i}" for i in range(expected_workers))}
    lifecycle = lifecycle and required_roles.issubset(physical_roles)
    timeline: dict[str, Timeline] = {}
    for label, selected in (
        ("T5_controller", [record for record in physical if record.get("role") == "controller"]),
        ("T4_workers", [record for record in physical if record.get("role") != "controller"]),
    ):
        exits = [
            record["first_exit"]
            for record in selected
            if isinstance(record.get("first_exit"), (int, float))
        ]
        status: Literal["unknown", "observed", "right-censored"] = "unknown"
        if selected and all(record.get("status") == "proved-exited" for record in selected):
            status = "observed" if len(exits) == len(selected) else "unknown"
        elif any(record.get("status") == "live" for record in selected):
            status = "right-censored"
        needed = {"controller"} if label == "T5_controller" else required_roles - {"controller"}
        if not needed.issubset(physical_roles):
            status = "unknown"
        timeline[label] = {"status": status, "observations": selected}
    complete = complete and root.get("event") == "exit" and root.get("root_code") in (0, 1)
    complete = complete and not root.get("observer_failed") and not root.get("interrupted")
    complete = complete and "root-exit" in supervisor.events
    environment = summaries.get("environment.jsonl", Parsed())
    provenance = next((r for r in environment.kept if r["event"] == "environment"), {})
    if not provenance or provenance.get("argv") != expected_run.get("argv"):
        complete = False
    if provenance.get("scope") == "published-source":
        for key in ("sha", "tree", "checkout_head", "service_sha", "service_head"):
            value = provenance.get(key)
            complete = (
                complete
                and isinstance(value, str)
                and re.fullmatch("[0-9a-f]{40}", value) is not None
            )
        complete = complete and provenance.get("sha") == provenance.get("checkout_head")
        complete = complete and provenance.get("service_sha") == provenance.get("service_head")
        packages = {
            package
            for record in environment.kept
            if record["event"] == "version" and isinstance(package := record.get("package"), str)
        }
        complete = complete and {
            "pytest",
            "pytest-xdist",
            "pytest-cov",
            "coverage",
            "psutil",
            "github-copilot-sdk",
            "claude-agent-sdk",
            "uv",
        }.issubset(packages)
    elif provenance.get("scope") != "synthetic-project":
        complete = False
    return Assessment(
        complete,
        lifecycle,
        root,
        provenance,
        timeline,
        frozenset(required_roles),
        frozenset(required_roles - phase_roles),
    )
