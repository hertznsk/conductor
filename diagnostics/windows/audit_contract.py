"""Consistency of structured receipts, separate from filesystem publication."""

from __future__ import annotations

import math
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
    cleanup: Record
    close_errors: tuple[Record, ...]
    close_warning: bool


def root_outcome(supervisor: Parsed, post: Parsed) -> Record:
    """Retain known Popen outcomes without treating a recovered receipt as an exit footer."""
    footer = supervisor.last if supervisor.last.get("event") == "exit" else {}
    ending = post.last if post.last.get("event") == "post.end" else {}
    exits = [r for r in supervisor.kept if r["event"] == "root-exit"]
    receipts = [("supervisor.exit", footer, "root_code")] if footer else []
    receipts += [("supervisor.root-exit", r, "exitcode") for r in exits]
    if ending:
        receipts.append(("post-root.post.end", ending, "root_code"))
    codes: list[int] = []
    invalid = False
    for _, record, field in receipts:
        code = record.get(field)
        if type(code) is int and isinstance(code, int):
            codes.append(code)
        else:
            invalid = True
    bindings = [r for r in supervisor.kept if r["event"] == "binding"]
    bound = False
    if len(bindings) == 1:
        identity = bindings[0].get("identity")
        physical = post.observations.get(identity, {}) if isinstance(identity, str) else {}
        first_exit = physical.get("first_exit")
        exit_at = exits[0].get("monotonic") if len(exits) == 1 else None
        ended_at = ending.get("monotonic")
        bound_at = bindings[0].get("monotonic")
        bound = (
            bool(physical)
            and physical.get("pid") == bindings[0].get("pid")
            and physical.get("created") == bindings[0].get("created")
            and physical.get("status") == "proved-exited"
            and isinstance(first_exit, (int, float))
            and math.isfinite(first_exit)
            and isinstance(exit_at, (int, float))
            and isinstance(ended_at, (int, float))
            and isinstance(bound_at, (int, float))
            and bound_at <= exit_at
            and first_exit <= exit_at <= ended_at
        )
    recovered = (
        not footer
        and len(exits) == 1
        and bool(ending)
        and bound
        and any(r.get("event") == "expected" and r.get("policy") == SCHEMA for r in supervisor.kept)
    )
    status = (
        "conflict"
        if len(set(codes)) > 1
        else "unknown"
        if invalid or not codes or (not footer and not recovered)
        else "observed"
        if footer
        else "recovered"
    )
    root: Record = {**(footer or ending)}
    root["root_code"] = codes[0] if status in ("observed", "recovered") else None
    root["outcome_status"] = status
    root["outcome_sources"] = [name for name, _, _ in receipts]
    root["outcome_codes"] = codes
    return root


def assess(
    summaries: Mapping[str, Parsed],
    phase_paths: Sequence[str],
    outcome_summaries: Mapping[str, Parsed] | None = None,
) -> Assessment:
    complete = True
    supervisor = summaries.get("supervisor.jsonl", Parsed())
    expected_run = next((r for r in supervisor.kept if r["event"] == "expected"), {})
    complete = expected_run.get("policy") == SCHEMA
    complete = complete and expected_run.get("expected_files") == list(MANDATORY_RECORDS)
    complete = complete and {"host", "process"}.issubset(
        summaries.get("processes.jsonl", Parsed()).events
    )
    complete = complete and not any(summary.producer_incomplete for summary in summaries.values())
    outcome_inputs = {**summaries, **(outcome_summaries or {})}
    root = root_outcome(
        outcome_inputs.get("supervisor.jsonl", Parsed()),
        outcome_inputs.get("post-root.jsonl", Parsed()),
    )
    root["outcome_validation"] = "validated-prefix" if outcome_summaries else "strict-records"
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
    complete = complete and all(worker.collection == controller.collection for worker in workers)
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
    frozen = post_summary.observations
    lifecycle = lifecycle and all(
        record.get("status") == "proved-exited"
        and isinstance(value := record.get("first_exit"), (int, float))
        and math.isfinite(value)
        for record in frozen.values()
    )
    observed = summaries.get("processes.jsonl", Parsed()).identities | {
        key
        for r in supervisor.kept
        if r["event"] == "binding" and isinstance(key := r.get("identity"), str)
    }
    lifecycle = lifecycle and set(frozen) == observed
    lifecycle = lifecycle and root.get("root_code") is not None
    lifecycle = lifecycle and not root.get("observer_failed") and not post.get("observer_failed")
    lifecycle = lifecycle and not supervisor.producer_incomplete
    fields = (
        "close_errors_count",
        "close_errors_recorded",
        "close_error_evidence_complete",
        "observer_cleanup_status",
    )
    cleanup = {key: root.get(key) for key in fields}
    close_errors = supervisor.close_errors
    close_ok = (
        all(root.get(key) == post.get(key) for key in fields)
        and cleanup["close_error_evidence_complete"] is True
        and type(cleanup["close_errors_count"]) is int
        and cleanup["close_errors_count"] == cleanup["close_errors_recorded"] == len(close_errors)
        and len(close_errors) <= 256
        and cleanup["observer_cleanup_status"]
        == ("close-error" if close_errors else "no-recorded-errors")
    )
    closed: set[str] = set()
    for record in close_errors:
        key, stamp, first_exit = (record.get(k) for k in ("identity", "monotonic", "first_exit"))
        final = frozen.get(key, {}) if isinstance(key, str) else {}
        qualified = (
            isinstance(key, str)
            and key not in closed
            and bool(final)
            and record.get("status") == final.get("status") == "proved-exited"
            and record.get("pid") == final.get("pid")
            and record.get("role") in (final.get("role"), "unknown", "root")
            and first_exit == final.get("first_exit")
            and isinstance(first_exit, (int, float))
            and math.isfinite(first_exit)
            and isinstance(stamp, (int, float))
            and first_exit <= stamp
            and record.get("stage") in ("observe-exited", "finish")
        )
        close_ok = close_ok and qualified
        if isinstance(key, str):
            closed.add(key)
    complete = complete and close_ok and (not close_errors or lifecycle)
    complete = complete and all(
        root.get(key) == post.get(key)
        for key in (
            "root_code",
            "interrupted",
            "observation_detached",
            "observer_failed",
            "complete",
        )
    )
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
        cleanup,
        tuple(close_errors),
        bool(close_errors) and close_ok and lifecycle and complete,
    )
