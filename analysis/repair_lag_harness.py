#!/usr/bin/env python3
"""Repair-lag / skip-repair harness for Narwhal lifecycle traces.

This offline harness reports active payload repair waiters that a hypothetical
round-only lifecycle policy would treat as old. It models a naive policy that
might skip or deprioritize repair for old objects. It does not delete data or
change Narwhal runtime behavior.
"""

import argparse
import csv
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import shadow_lifecycle as lifecycle


PAYLOAD_REPAIR_REASONS = {"missing_batch", "worker_sync"}


def repair_node(repair: lifecycle.RepairRecord) -> str:
    return repair.key[0]


def repair_source(repair: lifecycle.RepairRecord) -> str:
    return repair.key[1]


def repair_related_header(repair: lifecycle.RepairRecord) -> str:
    return repair.key[4]


def repair_certificate(repair: lifecycle.RepairRecord) -> str:
    return repair.key[5]


def repair_active_at(repair: lifecycle.RepairRecord, ts_ms: int) -> bool:
    return repair.added_at <= ts_ms and (repair.cleared_at is None or ts_ms < repair.cleared_at)


def digest_round_old(state: Optional[lifecycle.BatchState], ts_ms: int, cleanup_round: int) -> bool:
    if state is None:
        return False
    return (
        state.first_referenced_at is not None
        and state.first_referenced_at <= ts_ms
        and state.first_referenced_round is not None
        and state.first_referenced_round <= cleanup_round
    )


def local_payload_present_at(state: Optional[lifecycle.BatchState], ts_ms: int) -> bool:
    return (
        state is not None
        and state.size_bytes > 0
        and state.write_submitted_at is not None
        and state.write_submitted_at <= ts_ms
    )


def waiter_lifetime_ms(repair: lifecycle.RepairRecord) -> Optional[int]:
    if repair.cleared_at is None:
        return None
    return repair.cleared_at - repair.added_at


def candidate_to_clear_ms(repair: lifecycle.RepairRecord, candidate_ts_ms: int) -> Optional[int]:
    if repair.cleared_at is None:
        return None
    return repair.cleared_at - candidate_ts_ms


def repair_identity(repair: lifecycle.RepairRecord) -> Tuple[Tuple[str, str, str, str, str, str], int]:
    return repair.key, repair.added_at


def find_repair_lag_candidates(
    batches: Dict[str, lifecycle.BatchState],
    cleanup_events: List[dict],
    repairs: List[lifecycle.RepairRecord],
    args,
) -> tuple[List[dict], dict]:
    first_by_waiter: Dict[Tuple[Tuple[str, str, str, str, str, str], int], dict] = {}
    raw_decision_count = 0
    raw_decision_bytes_if_known = 0
    active_payload_repair_decision_count = 0
    unclassified_active_repair_decision_count = 0

    payload_repairs = [repair for repair in repairs if repair.reason in PAYLOAD_REPAIR_REASONS]

    for event in cleanup_events:
        ts_ms = int(event.get("ts_ms", 0))
        cleanup_round = lifecycle.policy_cleanup_round(event, args)

        for repair in payload_repairs:
            if not repair_active_at(repair, ts_ms):
                continue
            active_payload_repair_decision_count += 1

            state = batches.get(repair.missing_digest)
            if not digest_round_old(state, ts_ms, cleanup_round):
                if state is None or state.first_referenced_round is None:
                    unclassified_active_repair_decision_count += 1
                continue

            known_size_bytes = state.size_bytes if state is not None else 0
            raw_decision_count += 1
            raw_decision_bytes_if_known += known_size_bytes

            key = repair_identity(repair)
            existing = first_by_waiter.get(key)
            if existing is not None and int(existing["candidate_ts_ms"]) <= ts_ms:
                continue

            lifetime = waiter_lifetime_ms(repair)
            to_clear = candidate_to_clear_ms(repair, ts_ms)
            first_by_waiter[key] = {
                "missing_digest": repair.missing_digest,
                "candidate_ts_ms": ts_ms,
                "node": repair_node(repair),
                "source": repair_source(repair),
                "reason": repair.reason,
                "policy_cleanup_round": cleanup_round,
                "runtime_cleanup_round": lifecycle.runtime_cleanup_round(event),
                "policy_gc_depth": lifecycle.policy_gc_depth(event, args),
                "runtime_gc_depth": event.get("gc_depth", ""),
                "related_header_digest": repair_related_header(repair),
                "certificate_digest": repair_certificate(repair),
                "added_at": repair.added_at,
                "cleared_at": repair.cleared_at,
                "clear_reason": repair.clear_reason,
                "waiter_lifetime_ms": lifetime,
                "candidate_to_clear_ms": to_clear,
                "retry_count": repair.retry_count,
                "local_payload_present": local_payload_present_at(state, ts_ms),
                "known_size_bytes": known_size_bytes,
                "first_referenced_at": state.first_referenced_at if state else "",
                "first_referenced_round": state.first_referenced_round if state else "",
                "reference_age_rounds": cleanup_round - state.first_referenced_round
                if state and state.first_referenced_round is not None
                else "",
            }

    rows = sorted(first_by_waiter.values(), key=lambda x: (int(x["candidate_ts_ms"]), x["missing_digest"]))
    lifetimes = [int(row["waiter_lifetime_ms"]) for row in rows if row["waiter_lifetime_ms"] not in ("", None)]
    candidate_to_clear = [
        int(row["candidate_to_clear_ms"])
        for row in rows
        if row["candidate_to_clear_ms"] not in ("", None)
    ]
    totals = {
        "payload_repair_waiter_count": len(payload_repairs),
        "active_payload_repair_decision_count": active_payload_repair_decision_count,
        "unclassified_active_repair_decision_count": unclassified_active_repair_decision_count,
        "raw_skip_repair_candidate_count": raw_decision_count,
        "raw_skip_repair_candidate_bytes_if_known": raw_decision_bytes_if_known,
        "skip_repair_candidate_count": len(rows),
        "skip_repair_candidate_bytes_if_known": sum(int(row["known_size_bytes"]) for row in rows),
        "unique_missing_digest_count": len({row["missing_digest"] for row in rows}),
        "total_retries": sum(int(row["retry_count"]) for row in rows),
        "active_waiter_lifetime_ms": lifecycle.latency_summary(lifetimes),
        "candidate_to_clear_ms": lifecycle.latency_summary(candidate_to_clear),
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
        "--policy-gc-depth",
        type=int,
        default=None,
        help="Hypothetical round-only lifecycle gc_depth. Defaults to runtime cleanup_round from traces.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    events = lifecycle.read_events(args.trace)
    batches, commits, cleanup_events, repairs = lifecycle.replay(events)

    rows, totals = find_repair_lag_candidates(batches, cleanup_events, repairs, args)
    write_csv(args.out_dir / "repair_lag_candidates.csv", rows)

    summary = {
        "input_files": [str(x) for x in args.trace],
        "event_count": len(events),
        "batch_count": len(batches),
        "commit_count": len(commits),
        "cleanup_event_count": len(cleanup_events),
        "repair_waiter_count": len(repairs),
        "policy_gc_depth": args.policy_gc_depth,
        "policy_cleanup_runtime_fallback_count": lifecycle.policy_cleanup_runtime_fallback_count(
            cleanup_events,
            args,
        ),
        **totals,
        "interpretation": (
            "Each row is a unique active payload repair waiter whose missing digest is round-old "
            "under a hypothetical round-only policy. These are skip/deprioritize-repair "
            "candidates, not real Narwhal pruning actions."
        ),
    }
    (args.out_dir / "repair_lag_summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
