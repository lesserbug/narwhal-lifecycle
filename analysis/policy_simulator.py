#!/usr/bin/env python3
"""Offline lifecycle policy simulator for Narwhal lifecycle traces.

The simulator classifies payload bytes as prune candidates under simple
hypothetical policies. It does not delete data and does not model Narwhal's
runtime behavior as performing physical pruning.
"""

import argparse
import csv
import json
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional

import shadow_lifecycle as lifecycle


PolicyFn = Callable[[lifecycle.BatchState, int, int, Optional[int], argparse.Namespace], bool]


def local_payload_present_at(state: lifecycle.BatchState, ts_ms: int) -> bool:
    return (
        state.size_bytes > 0
        and state.write_submitted_at is not None
        and state.write_submitted_at <= ts_ms
    )


def round_old(state: lifecycle.BatchState, ts_ms: int, cleanup_round: int) -> bool:
    return (
        state.first_referenced_at is not None
        and state.first_referenced_at <= ts_ms
        and state.first_referenced_round is not None
        and state.first_referenced_round <= cleanup_round
    )


def checkpoint_ready(state: lifecycle.BatchState, ts_ms: int) -> bool:
    return (
        state.executed_at is not None
        and state.executed_at <= ts_ms
        and state.checkpointed_at is not None
        and state.checkpointed_at <= ts_ms
    )


def large_cleanup_round(committed_round: Optional[int], fallback_cleanup_round: int, args) -> int:
    if committed_round is None:
        return fallback_cleanup_round
    return max(0, committed_round - args.large_policy_gc_depth)


def never_prune(
    state: lifecycle.BatchState,
    ts_ms: int,
    cleanup_round: int,
    committed_round: Optional[int],
    args,
) -> bool:
    return False


def round_only(
    state: lifecycle.BatchState,
    ts_ms: int,
    cleanup_round: int,
    committed_round: Optional[int],
    args,
) -> bool:
    return round_old(state, ts_ms, cleanup_round)


def large_gc_depth(
    state: lifecycle.BatchState,
    ts_ms: int,
    cleanup_round: int,
    committed_round: Optional[int],
    args,
) -> bool:
    return round_old(state, ts_ms, large_cleanup_round(committed_round, cleanup_round, args))


def checkpoint_only(
    state: lifecycle.BatchState,
    ts_ms: int,
    cleanup_round: int,
    committed_round: Optional[int],
    args,
) -> bool:
    return checkpoint_ready(state, ts_ms)


def round_plus_checkpoint(
    state: lifecycle.BatchState,
    ts_ms: int,
    cleanup_round: int,
    committed_round: Optional[int],
    args,
) -> bool:
    return round_old(state, ts_ms, cleanup_round) and checkpoint_ready(state, ts_ms)


def proof_gated_shadow(
    state: lifecycle.BatchState,
    ts_ms: int,
    cleanup_round: int,
    committed_round: Optional[int],
    args,
) -> bool:
    live_reason = lifecycle.why_live_at(state, ts_ms, args.repairs)
    return live_reason == "not_live"


POLICIES: Dict[str, PolicyFn] = {
    "never-prune": never_prune,
    "round-only": round_only,
    "large-gc-depth": large_gc_depth,
    "checkpoint-only": checkpoint_only,
    "round+checkpoint": round_plus_checkpoint,
    "proof-gated-shadow": proof_gated_shadow,
}


COUNT_FIELDS = (
    "total_local_payload_count",
    "prune_candidate_count",
    "unsafe_candidate_count",
    "over_retained_count",
    "execution_needed_but_candidate_count",
    "repair_needed_but_candidate_count",
    "checkpoint_pending_but_candidate_count",
    "referenced_unknown_but_candidate_count",
    "unknown_candidate_count",
    "unknown_retained_count",
)

BYTE_FIELDS = (
    "total_local_payload_bytes",
    "prune_candidate_bytes",
    "unsafe_candidate_bytes",
    "over_retained_bytes",
    "execution_needed_but_candidate_bytes",
    "repair_needed_but_candidate_bytes",
    "checkpoint_pending_but_candidate_bytes",
    "referenced_unknown_but_candidate_bytes",
    "unknown_candidate_bytes",
    "unknown_retained_bytes",
)


def empty_metrics() -> dict:
    metrics = {}
    for field in COUNT_FIELDS + BYTE_FIELDS:
        metrics[field] = 0
    return metrics


def add_metric(metrics: dict, count_field: str, byte_field: str, size_bytes: int) -> None:
    metrics[count_field] += 1
    metrics[byte_field] += size_bytes


def classify_policy(
    policy_name: str,
    policy_fn: PolicyFn,
    ts_ms: int,
    cleanup_round: int,
    committed_round: Optional[int],
    batches: Dict[str, lifecycle.BatchState],
    args,
) -> dict:
    metrics = empty_metrics()

    for state in batches.values():
        if not local_payload_present_at(state, ts_ms):
            continue

        size_bytes = state.size_bytes
        add_metric(metrics, "total_local_payload_count", "total_local_payload_bytes", size_bytes)

        candidate = policy_fn(state, ts_ms, cleanup_round, committed_round, args)
        live_reason = lifecycle.why_live_at(state, ts_ms, args.repairs)
        shadow_live = live_reason != "not_live"

        if candidate:
            add_metric(metrics, "prune_candidate_count", "prune_candidate_bytes", size_bytes)
            if shadow_live:
                add_metric(metrics, "unsafe_candidate_count", "unsafe_candidate_bytes", size_bytes)
                add_candidate_reason(metrics, live_reason, size_bytes)
        elif not shadow_live:
            add_metric(metrics, "over_retained_count", "over_retained_bytes", size_bytes)
        elif live_reason == "unknown_or_insufficient_trace":
            add_metric(metrics, "unknown_retained_count", "unknown_retained_bytes", size_bytes)

    return {
        "policy": policy_name,
        **metrics,
    }


def add_candidate_reason(metrics: dict, live_reason: str, size_bytes: int) -> None:
    if live_reason == "committed_not_executed":
        add_metric(
            metrics,
            "execution_needed_but_candidate_count",
            "execution_needed_but_candidate_bytes",
            size_bytes,
        )
    elif live_reason == "repair_waiter_active":
        add_metric(
            metrics,
            "repair_needed_but_candidate_count",
            "repair_needed_but_candidate_bytes",
            size_bytes,
        )
    elif live_reason == "checkpoint_pending":
        add_metric(
            metrics,
            "checkpoint_pending_but_candidate_count",
            "checkpoint_pending_but_candidate_bytes",
            size_bytes,
        )
    elif live_reason == "referenced_not_committed_or_unknown":
        add_metric(
            metrics,
            "referenced_unknown_but_candidate_count",
            "referenced_unknown_but_candidate_bytes",
            size_bytes,
        )
    elif live_reason == "unknown_or_insufficient_trace":
        add_metric(metrics, "unknown_candidate_count", "unknown_candidate_bytes", size_bytes)


def policy_rows_for_cleanup(
    event: dict,
    batches: Dict[str, lifecycle.BatchState],
    args,
) -> List[dict]:
    ts_ms = int(event.get("ts_ms", 0))
    cleanup_round = lifecycle.policy_cleanup_round(event, args)
    runtime_cleanup_round = lifecycle.runtime_cleanup_round(event)
    committed_round = lifecycle.int_or_none(event.get("committed_round"))
    rows = []

    for policy_name, policy_fn in POLICIES.items():
        row = {
            "ts_ms": ts_ms,
            "source": event.get("source", ""),
            "policy": policy_name,
            "committed_round": event.get("committed_round", ""),
            "policy_cleanup_round": cleanup_round,
            "runtime_cleanup_round": runtime_cleanup_round,
            "policy_gc_depth": lifecycle.policy_gc_depth(event, args),
            "runtime_gc_depth": event.get("gc_depth", ""),
            "large_policy_gc_depth": args.large_policy_gc_depth if policy_name == "large-gc-depth" else "",
        }
        row.update(classify_policy(policy_name, policy_fn, ts_ms, cleanup_round, committed_round, batches, args))
        rows.append(row)

    return rows


def write_policy_timeseries(
    out_dir: Path,
    cleanup_events: List[dict],
    batches: Dict[str, lifecycle.BatchState],
    args,
) -> List[dict]:
    rows = []
    for event in cleanup_events:
        rows.extend(policy_rows_for_cleanup(event, batches, args))
    write_csv(out_dir / "policy_timeseries.csv", rows)
    return rows


def summarize_policy_timeseries(rows: List[dict]) -> List[dict]:
    by_policy: Dict[str, List[dict]] = {}
    for row in rows:
        by_policy.setdefault(row["policy"], []).append(row)

    summary_rows = []
    for policy, policy_rows in by_policy.items():
        last = policy_rows[-1]
        summary = {
            "policy": policy,
            "last_ts_ms": last.get("ts_ms", ""),
            "last_committed_round": last.get("committed_round", ""),
            "last_policy_cleanup_round": last.get("policy_cleanup_round", ""),
            "last_runtime_cleanup_round": last.get("runtime_cleanup_round", ""),
            "policy_gc_depth": last.get("policy_gc_depth", ""),
            "large_policy_gc_depth": last.get("large_policy_gc_depth", ""),
        }
        for field in COUNT_FIELDS + BYTE_FIELDS:
            summary[f"last_{field}"] = int_field(last, field)
            summary[f"max_{field}"] = max(int_field(row, field) for row in policy_rows)
        summary_rows.append(summary)

    return summary_rows


def int_field(row: dict, field: str) -> int:
    value = row.get(field, 0)
    if value in ("", None):
        return 0
    return int(float(value))


def write_csv(path: Path, rows: List[dict]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields = []
    for row in rows:
        for key in row:
            if key == "_out_dir":
                continue
            if key not in fields:
                fields.append(key)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", nargs="+", required=True, type=Path, help="JSONL trace files")
    parser.add_argument("--out-dir", required=True, type=Path, help="Directory for simulator outputs")
    parser.add_argument(
        "--execution",
        choices=("fast", "slow", "bursty"),
        default="fast",
        help="Mock execution strategy",
    )
    parser.add_argument("--execution-delay-ms", type=int, default=1000)
    parser.add_argument("--bursty-period-ms", type=int, default=60000)
    parser.add_argument("--bursty-pause-ms", type=int, default=10000)
    parser.add_argument("--checkpoint-every", type=int, default=100)
    parser.add_argument("--checkpoint-interval-ms", type=int, default=0)
    parser.add_argument(
        "--policy-gc-depth",
        type=int,
        default=None,
        help="Hypothetical round-only lifecycle gc_depth. Defaults to runtime cleanup_round from traces.",
    )
    parser.add_argument(
        "--large-policy-gc-depth",
        type=int,
        default=100,
        help="gc_depth used by the large-gc-depth comparison policy",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.execution == "slow" and args.execution_delay_ms == 1000:
        args.execution_delay_ms = 30000

    args.out_dir.mkdir(parents=True, exist_ok=True)
    events = lifecycle.read_events(args.trace)
    batches, commits, cleanup_events, repairs = lifecycle.replay(events)
    lifecycle.apply_mock_execution(commits, args)
    lifecycle.propagate_mock_times(batches, commits)

    args.repairs = repairs
    rows = write_policy_timeseries(args.out_dir, cleanup_events, batches, args)
    summary_rows = summarize_policy_timeseries(rows)

    summary = {
        "input_files": [str(x) for x in args.trace],
        "event_count": len(events),
        "batch_count": len(batches),
        "commit_count": len(commits),
        "cleanup_event_count": len(cleanup_events),
        "repair_waiter_count": len(repairs),
        "policy_count": len(POLICIES),
        "policy_gc_depth": args.policy_gc_depth,
        "large_policy_gc_depth": args.large_policy_gc_depth,
        "checkpoint_every": args.checkpoint_every,
        "checkpoint_interval_ms": args.checkpoint_interval_ms,
        "execution_delay_ms": args.execution_delay_ms,
        "policy_cleanup_runtime_fallback_count": lifecycle.policy_cleanup_runtime_fallback_count(
            cleanup_events,
            args,
        ),
        "interpretation": (
            "All destructive actions are hypothetical prune candidates. This simulator compares "
            "offline policies against the derived shadow lifecycle view and does not delete data."
        ),
    }
    (args.out_dir / "policy_simulator_summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )
    write_csv(args.out_dir / "policy_summary.csv", summary_rows)


if __name__ == "__main__":
    main()
