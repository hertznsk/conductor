"""Bounded comparison reducers. Partial measurements never upgrade the raw artifact audit."""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field

from artifact_policy import Record, Sanitizer
from artifact_snapshot import Prefix
from record_schema import TimingWorker

type Json = str | int | float | bool | None | Sequence[Json] | Mapping[str, Json]


@dataclass(slots=True)
class Summary:
    """Accumulate explicit provenance and reduced measurements, never raw per-item evidence."""

    source_bytes: int = 0
    validated_bytes: int = 0
    records_consumed: int = 0
    first_monotonic: float | None = None
    last_monotonic: float | None = None
    terminal_event_seen: bool = False
    discarded_tail_bytes: int = 0
    gap_count: int = 0
    error_counts: dict[str, int] = field(default_factory=dict)
    right_censored: bool = True
    measurement_status: str = "unavailable"
    sha256: str = ""
    sources: list[dict[str, Json]] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    bounds: dict[str, Json] = field(
        default_factory=lambda: {
            "input_bytes_per_source": 64 * 1024 * 1024,
            "summary_bytes": 1024 * 1024,
            "activity_buckets": 128,
            "top_files": 50,
            "detail_reduced": True,
        }
    )
    measurements: dict[str, Json] = field(default_factory=dict)


def provenance(inputs: Mapping[str, Prefix]) -> Summary:
    result = Summary()
    digest = hashlib.sha256()
    for name, prefix in sorted(inputs.items()):
        meta = {key: value for key, value in asdict(prefix).items() if key != "content"}
        result.sources.append({"source": name, **meta})
        digest.update(prefix.content)
        result.source_bytes += prefix.source_bytes
        result.validated_bytes += prefix.validated_bytes
        result.records_consumed += prefix.records_consumed
        result.discarded_tail_bytes += prefix.discarded_tail_bytes
        result.gap_count += prefix.gap_count
        for key, count in prefix.error_counts.items():
            result.error_counts[key] = result.error_counts.get(key, 0) + count
    starts = [p.first_monotonic for p in inputs.values() if p.first_monotonic is not None]
    ends = [p.last_monotonic for p in inputs.values() if p.last_monotonic is not None]
    result.first_monotonic, result.last_monotonic = (
        min(starts, default=None),
        max(ends, default=None),
    )
    result.terminal_event_seen = bool(inputs) and all(
        p.terminal_event_seen for p in inputs.values()
    )
    result.right_censored = not inputs or any(p.right_censored for p in inputs.values())
    result.sha256 = digest.hexdigest()
    return result


def number(record: Mapping[str, Json], key: str) -> float | None:
    value = record.get(key)
    return float(value) if type(value) in (int, float) and isinstance(value, (int, float)) else None


def deltas(current: Record, previous: Record, keys: tuple[str, ...]) -> dict[str, float]:
    return {
        key: now - before
        for key in keys
        if (now := number(current, key)) is not None
        and (before := number(previous, key)) is not None
    }


def summarize_resources(inputs: Mapping[str, Prefix], sanitizer: Sanitizer) -> Summary:
    result = provenance(inputs)
    result.terminal_event_seen = all(
        inputs.get(name, Prefix()).terminal_event_seen
        for name in ("supervisor.jsonl", "post-root.jsonl")
    )
    result.right_censored = not result.terminal_event_seen or any(
        p.error_counts or p.discarded_tail_bytes for p in inputs.values()
    )
    latest: dict[str, Record] = {}
    roles: dict[str, str] = {}
    ends: dict[str, float] = {}
    mandatory = {"controller", "gw0"}
    for name, prefix in inputs.items():
        for r in prefix.records(sanitizer):
            if r["event"] == "expected" and r.get("workers") == 2:
                mandatory.add("gw1")
            if name == "supervisor.jsonl":
                continue
            key, role = r.get("identity"), r.get("role")
            if isinstance(key, str) and isinstance(role, str):
                if key not in roles or role not in ("root", "unknown"):
                    roles[key] = role
                ends[key] = number(r, "first_exit") or number(r, "monotonic") or 0
    groups: dict[str, dict[str, Json]] = {}
    missed: Counter[str] = Counter()
    valid: Counter[str] = Counter()
    affinity_changed: set[str] = set()
    host: dict[str, Json] = {
        "intervals": 0,
        "cpu_busy_seconds": None,
        "cpu_total_seconds": None,
        "read_bytes_delta": None,
        "write_bytes_delta": None,
        "sampled_available_memory_min": None,
        "sampled_available_memory_max": None,
        "first_monotonic": None,
        "last_monotonic": None,
    }
    previous_host: Record = {}
    host_interval_seconds = 0.0
    buckets: dict[int, dict[str, Json]] = {}
    prefix = inputs.get("processes.jsonl", Prefix())
    span = max(1.0, (prefix.last_monotonic or 0) - (prefix.first_monotonic or 0))
    for r in prefix.records(sanitizer):
        stamp = number(r, "monotonic") or 0
        bucket = min(
            127,
            int(
                128
                * (
                    stamp
                    - (prefix.first_monotonic if prefix.first_monotonic is not None else stamp)
                )
                / span
            ),
        )
        activity = buckets.setdefault(bucket, {"bucket": bucket, "samples": 0})
        if r["event"] == "host":
            host["first_monotonic"] = (
                stamp if host["first_monotonic"] is None else host["first_monotonic"]
            )
            host["last_monotonic"] = stamp
            activity["samples"] = (number(activity, "samples") or 0) + 1
            memory = number(r, "memory_available")
            if memory is not None:
                old = number(host, "sampled_available_memory_min")
                host["sampled_available_memory_min"] = (
                    min(old, memory) if old is not None else memory
                )
                host["sampled_available_memory_max"] = max(
                    number(host, "sampled_available_memory_max") or 0, memory
                )
            previous_stamp = number(previous_host, "monotonic")
            dt = stamp - previous_stamp if previous_stamp is not None else 0
            delta = deltas(r, previous_host, ("cpu_total", "cpu_idle", "read_bytes", "write_bytes"))
            if dt > 0 and len(delta) == 4 and min(delta.values()) >= 0:
                host_interval_seconds += dt
                host["intervals"] = (number(host, "intervals") or 0) + 1
                for key, value in (
                    ("cpu_busy_seconds", delta["cpu_total"] - delta["cpu_idle"]),
                    ("cpu_total_seconds", delta["cpu_total"]),
                    ("read_bytes_delta", delta["read_bytes"]),
                    ("write_bytes_delta", delta["write_bytes"]),
                ):
                    host[key] = (number(host, key) or 0) + value
                if dt > 30:
                    result.reasons.append("host-sample-gap")
            elif previous_host:
                result.reasons.append("host-counters-reset-or-missing")
            previous_host = r
        if r["event"] == "observer.error" and isinstance(r.get("identity"), str):
            missed[str(r["identity"])] += 1
        if r["event"] != "process":
            continue
        key = str(r.get("identity"))
        role = roles.get(key, str(r.get("role", "unknown")))
        group = role if role in ("controller", "gw0", "gw1") else "other-known"
        g = groups.setdefault(
            group,
            {
                "cpu_seconds": None,
                "read_bytes_delta": None,
                "write_bytes_delta": None,
                "sampled_rss_max": None,
                "sampled_vms_max": None,
                "first_monotonic": stamp,
                "last_monotonic": stamp,
                "cpu_cores": None,
                "percent_measured_affinity": None,
                "measured_identities": 0,
                "missed_identities": 0,
            },
        )
        g["last_monotonic"] = stamp
        for metric in ("rss", "vms"):
            value = number(r, metric)
            if value is not None:
                metric = "sampled_" + metric + "_max"
                g[metric] = max(number(g, metric) or 0, value)
        previous = latest.get(key, {})
        previous_stamp = number(previous, "monotonic")
        dt = stamp - previous_stamp if previous_stamp is not None else 0
        metrics = ("cpu_user", "cpu_system", "read_bytes", "write_bytes")
        delta = deltas(r, previous, metrics)
        if previous:
            if previous.get("affinity") != r.get("affinity"):
                affinity_changed.add(key)
            if dt <= 0 or len(delta) != 4 or min(delta.values()) < 0:
                missed[key] += 1
                result.error_counts["counter-reset-or-missing"] = (
                    result.error_counts.get("counter-reset-or-missing", 0) + 1
                )
            else:
                valid[key] += 1
                for metric, value in (
                    ("cpu_seconds", delta["cpu_user"] + delta["cpu_system"]),
                    ("read_bytes_delta", delta["read_bytes"]),
                    ("write_bytes_delta", delta["write_bytes"]),
                ):
                    g[metric] = (number(g, metric) or 0) + value
                if (
                    dt > 30
                    or (number(r, "sample_id") or 0) - (number(previous, "sample_id") or 0) > 1
                ):
                    missed[key] += 1
        latest[key] = r
    for key in roles.keys() | latest.keys():
        role = roles.get(key, str(latest.get(key, {}).get("role", "unknown")))
        group = role if role in ("controller", "gw0", "gw1") else "other-known"
        g = groups.setdefault(
            group,
            {
                "cpu_seconds": None,
                "read_bytes_delta": None,
                "write_bytes_delta": None,
                "sampled_rss_max": None,
                "sampled_vms_max": None,
                "first_monotonic": None,
                "last_monotonic": None,
                "cpu_cores": None,
                "percent_measured_affinity": None,
                "measured_identities": 0,
                "missed_identities": 0,
            },
        )
        if valid[key]:
            g["measured_identities"] = (number(g, "measured_identities") or 0) + 1
        if missed[key] or not valid[key]:
            g["missed_identities"] = (number(g, "missed_identities") or 0) + 1
        if role in mandatory and (
            not valid[key]
            or missed[key]
            or ends.get(key, prefix.last_monotonic or 0)
            - (number(latest.get(key, {}), "monotonic") or 0)
            > 20
        ):
            result.reasons.append("mandatory-role-samples-incomplete")
    for role in sorted(mandatory):
        if role not in groups:
            result.reasons.append("mandatory-role-missing")
    for group, g in groups.items():
        elapsed = (number(g, "last_monotonic") or 0) - (number(g, "first_monotonic") or 0)
        if elapsed > 0 and g["cpu_seconds"] is not None:
            g["cpu_cores"] = (number(g, "cpu_seconds") or 0) / elapsed
            affinities = [
                r.get("affinity") for k, r in latest.items() if roles.get(k, r.get("role")) == group
            ]
            affinity = affinities[0] if affinities else None
            stable = not any(
                k in affinity_changed
                for k in latest
                if roles.get(k, latest[k].get("role")) == group
            )
            if (
                isinstance(affinity, list)
                and affinity
                and stable
                and all(a == affinity for a in affinities)
            ):
                g["percent_measured_affinity"] = (number(g, "cpu_cores") or 0) * 100 / len(affinity)
    busy, total = host["cpu_busy_seconds"], host["cpu_total_seconds"]
    host["cpu_cores"] = (
        (number(host, "cpu_busy_seconds") or 0) / host_interval_seconds
        if busy is not None and host_interval_seconds
        else None
    )
    host["cpu_percent"] = (
        100 * (number(host, "cpu_busy_seconds") or 0) / (number(host, "cpu_total_seconds") or 1)
        if busy is not None and total
        else None
    )
    host["observation_interval_seconds"] = host_interval_seconds
    host["first_cpu_percent_ignored"] = True
    if result.right_censored:
        result.reasons.append("observation-right-censored")
    if affinity_changed:
        result.reasons.append("affinity-changed")
    result.reasons = sorted(set(result.reasons))
    if not host["intervals"]:
        result.reasons.append("host-insufficient-samples")
    result.measurement_status = (
        "unavailable"
        if not latest
        else "insufficient-samples"
        if any(reason.startswith("mandatory-") for reason in result.reasons)
        else "limited"
        if result.right_censored or result.error_counts or result.reasons
        else "measured"
    )
    result.measurements = {
        "groups": groups,
        "host": host,
        "activity": list(buckets.values()),
        "missed_sample_intervals": sum(missed.values()),
        "short_lived_costs": "lower-bound",
        "memory_semantics": "sampled-maxima-per-identity",
        "io_semantics": "process-counters-not-disk-latency",
    }
    return result


def summarize_timing(inputs: Mapping[str, Prefix], sanitizer: Sanitizer) -> Summary:
    result = provenance(inputs)
    workers: dict[str, TimingWorker] = {}
    milestones: dict[str, Json] = {}
    files: dict[str, dict[str, Json]] = {}
    buckets: Counter[int] = Counter()
    span = max(1.0, (result.last_monotonic or 0) - (result.first_monotonic or 0))
    for name, prefix in sorted(inputs.items()):
        opened: dict[tuple[int, str], float] = {}
        role = "unknown"
        for r in prefix.records(sanitizer):
            stamp = number(r, "monotonic") or 0
            event = str(r["event"])
            role = str(r.get("worker", "supervisor"))
            if event in (
                "start",
                "launch",
                "root-exit",
                "sessionfinish.begin",
                "sessionfinish.end",
                "worker-down",
            ) or (event == "configured" and "collected" in r):
                milestones[role + ":" + event + ":" + str(r.get("name", ""))] = stamp
            if not name.endswith(".phase.jsonl"):
                continue
            w = workers.setdefault(
                role,
                TimingWorker("controller-receive" if role == "controller" else "worker-monotonic"),
            )
            index = r.get("item_index")
            if type(index) is not int or not isinstance(index, int):
                continue
            if event != "collected":
                w.last_active_item_index = index
            phase = event.partition(".")[0]
            if role != "controller" and phase in ("setup", "call", "teardown"):
                key = (index, phase)
                if event.endswith(".begin"):
                    opened[key] = stamp
                elif event.endswith(".end") and key in opened:
                    start = opened.pop(key)
                    w.phase_wall_seconds[phase] = w.phase_wall_seconds.get(phase, 0) + stamp - start
                    old = w.phase_intervals.get(phase)
                    w.phase_intervals[phase] = [min(old[0], start) if old else start, stamp]
            if event == "report":
                phase = str(r.get("phase"))
                outcome = phase + ":" + str(r.get("outcome"))
                w.reported_duration_sum[phase] = w.reported_duration_sum.get(phase, 0) + (
                    number(r, "duration") or 0
                )
                w.completed_outcomes[outcome] = w.completed_outcomes.get(outcome, 0) + 1
            if event != "collected":
                filename = str(r.get("label", "")).partition("::")[0]
                f = files.setdefault(
                    filename, {"file": filename, "first": stamp, "last": stamp, "reports": 0}
                )
                f["first"], f["last"] = (
                    min(number(f, "first") or 0, stamp),
                    max(number(f, "last") or 0, stamp),
                )
                f["reports"] = (number(f, "reports") or 0) + (event == "report")
                start = result.first_monotonic if result.first_monotonic is not None else stamp
                buckets[min(127, int(128 * (stamp - start) / span))] += 1
        if name.endswith(".phase.jsonl") and opened:
            result.right_censored = True
            workers[role].open_phases = [
                {"item_index": i, "phase": p, "begin": t, "observed_until": prefix.last_monotonic}
                for (i, p), t in list(opened.items())[:128]
            ]
            result.reasons.append("open-phases")
    result.measurement_status = (
        "unavailable" if not workers else "limited" if result.right_censored else "measured"
    )
    result.measurements = {
        "workers": {role: asdict(w) for role, w in workers.items()},
        "milestones": milestones,
        "files_top50": sorted(
            files.values(),
            key=lambda f: (-((number(f, "last") or 0) - (number(f, "first") or 0)), str(f["file"])),
        )[:50],
        "activity": [{"bucket": i, "events": n} for i, n in sorted(buckets.items())],
        "phase_sum_semantics": "worker-phase-duration-sums-are-not-wall-time",
    }
    return result
