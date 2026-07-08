#!/usr/bin/env python3
"""Execution-lag failure harness for Narwhal lifecycle traces.

This is an offline harness. It reports payloads that a hypothetical round-only
lifecycle policy would mark as prune candidates before mock execution consumes
them. It does not delete data or change Narwhal runtime behavior.
"""

import argparse
import csv
import json
from pathlib import Path
from typing import Dict, List

import shadow_lifecycle as lifecycle


def local_payload_present_at(state: lifecycle.BatchState, ts_ms: int) -> bool:
    return (
        state.size_bytes > 0
        and state.write_submitted_at is not None
        and state.write_submitted_at <= ts_ms
    )


def round_only_candidate(state: lifecycle.BatchState, ts_ms: int, cleanup_round: int) -> bool:
    return (
        state.first_referenced_at is not None
        and state.first_referenced_at <= ts_ms
        and state.first_referenced_round is not None
        and state.first_referenced_round <= cleanup_round
    )


def execution_needed_after_candidate(state: lifecycle.BatchState, ts_ms: int) -> bool:
    return state.executed_at is not None and ts_ms < state.executed_at


def find_execution_lag_candidates(
    batches: Dict[str, lifecycle.BatchState],
    cleanup_events: List[dict],
    repairs: List[lifecycle.RepairRecord],
    args,
) -> tuple[List[dict], dict]:
    first_by_digest: Dict[str, dict] = {}
    raw_decision_count = 0
    raw_decision_bytes = 0

    for event in cleanup_events:
        ts_ms = int(event.get("ts_ms", 0))
        cleanup_round = lifecycle.policy_cleanup_round(event, args)

        for digest, state in batches.items():
            if not local_payload_present_at(state, ts_ms):
                continue
            if not round_only_candidate(state, ts_ms, cleanup_round):
                continue
            if lifecycle.why_live_at(state, ts_ms, repairs) != "committed_not_executed":
                continue
            if not execution_needed_after_candidate(state, ts_ms):
                continue

            raw_decision_count += 1
            raw_decision_bytes += state.size_bytes

            existing = first_by_digest.get(digest)
            if existing is not None and int(existing["candidate_ts_ms"]) <= ts_ms:
                continue

            first_by_digest[digest] = {
                "digest": digest,
                "candidate_ts_ms": ts_ms,
                "source": event.get("source", ""),
                "committed_round_at_candidate": event.get("committed_round", ""),
                "policy_cleanup_round": cleanup_round,
                "runtime_cleanup_round": lifecycle.runtime_cleanup_round(event),
                "policy_gc_depth": lifecycle.policy_gc_depth(event, args),
                "runtime_gc_depth": event.get("gc_depth", ""),
                "size_bytes": state.size_bytes,
                "first_referenced_at": state.first_referenced_at,
                "first_referenced_round": state.first_referenced_round,
                "committed_at": state.committed_at,
                "payload_committed_round": state.committed_round,
                "mock_executed_at": state.executed_at,
                "lag_until_execution_ms": state.executed_at - ts_ms,
            }

    rows = sorted(first_by_digest.values(), key=lambda x: (int(x["candidate_ts_ms"]), x["digest"]))
    totals = {
        "raw_candidate_decision_count": raw_decision_count,
        "raw_candidate_decision_bytes": raw_decision_bytes,
        "stall_equivalent_events": len(rows),
        "unique_candidate_bytes": sum(int(row["size_bytes"]) for row in rows),
    }
    return rows, totals


def write_csv(path: Path, rows: List[dict]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", nargs="+", required=True, type=Path, help="JSONL trace files")
    parser.add_argument("--out-dir", required=True, type=Path, help="Directory for harness outputs")
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

    rows, totals = find_execution_lag_candidates(batches, cleanup_events, repairs, args)
    write_csv(args.out_dir / "execution_lag_candidates.csv", rows)

    lag_values = [int(row["lag_until_execution_ms"]) for row in rows]
    summary = {
        "input_files": [str(x) for x in args.trace],
        "event_count": len(events),
        "batch_count": len(batches),
        "commit_count": len(commits),
        "cleanup_event_count": len(cleanup_events),
        "repair_waiter_count": len(repairs),
        "policy_gc_depth": args.policy_gc_depth,
        "checkpoint_every": args.checkpoint_every,
        "checkpoint_interval_ms": args.checkpoint_interval_ms,
        "execution_delay_ms": args.execution_delay_ms,
        "policy_cleanup_runtime_fallback_count": lifecycle.policy_cleanup_runtime_fallback_count(
            cleanup_events,
            args,
        ),
        **totals,
        "lag_until_execution_ms": lifecycle.latency_summary(lag_values),
        "interpretation": (
            "Each row is a unique local payload digest whose earliest round-only prune candidate "
            "time precedes mock execution. These are hypothetical failure candidates, not real "
            "Narwhal deletions."
        ),
    }
    (args.out_dir / "execution_lag_summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
