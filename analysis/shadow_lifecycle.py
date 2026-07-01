#!/usr/bin/env python3
"""Offline shadow lifecycle view for Narwhal lifecycle JSONL traces.

This script characterizes a hypothetical round-based payload lifecycle policy
against a derived local-obligation view. It does not model or authorize real
payload deletion in the Narwhal baseline.
"""

import argparse
import csv
import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


@dataclass
class BatchState:
    digest: str
    write_submitted_at: Optional[int] = None
    marker_submitted_at: Optional[int] = None
    size_bytes: int = 0
    references: Dict[str, int] = field(default_factory=dict)
    first_referenced_at: Optional[int] = None
    first_referenced_round: Optional[int] = None
    committed_at: Optional[int] = None
    committed_round: Optional[int] = None
    executed_at: Optional[int] = None
    checkpointed_at: Optional[int] = None


@dataclass
class CommitRecord:
    ts_ms: int
    certificate_digest: str
    round: int
    payload_digests: List[str]
    executed_at: Optional[int] = None
    checkpointed_at: Optional[int] = None


@dataclass
class RepairRecord:
    key: Tuple[str, str, str, str, str, str]
    reason: str
    missing_digest: str
    added_at: int
    cleared_at: Optional[int] = None
    clear_reason: Optional[str] = None
    retry_count: int = 0


def read_events(paths: Iterable[Path]) -> List[dict]:
    events = []
    for file_index, path in enumerate(paths):
        with path.open("r", encoding="utf-8") as f:
            for line_index, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                event = json.loads(line)
                event.setdefault("_file", str(path))
                event.setdefault("_file_index", file_index)
                event.setdefault("_line_index", line_index)
                events.append(event)
    events.sort(
        key=lambda x: (
            int(x.get("ts_ms", 0)),
            int(x.get("seq", 0)),
            x["_file_index"],
            x["_line_index"],
        )
    )
    return events


def batch_for(batches: Dict[str, BatchState], digest: str) -> BatchState:
    state = batches.get(digest)
    if state is None:
        state = BatchState(digest=digest)
        batches[digest] = state
    return state


def repair_key(event: dict) -> Tuple[str, str, str, str, str, str]:
    return (
        str(event.get("node", "")),
        str(event.get("source", "")),
        str(event.get("reason", "")),
        str(event.get("missing_digest", "")),
        str(event.get("related_header_digest", "")),
        str(event.get("certificate_digest", "")),
    )


def replay(events: List[dict]) -> Tuple[Dict[str, BatchState], List[CommitRecord], List[dict], List[RepairRecord]]:
    batches: Dict[str, BatchState] = {}
    commits: List[CommitRecord] = []
    cleanup_events: List[dict] = []
    active_repairs: Dict[Tuple[str, str, str, str, str, str], List[RepairRecord]] = {}
    repair_records: List[RepairRecord] = []

    for event in events:
        name = event.get("event")
        ts_ms = int(event.get("ts_ms", 0))

        if name == "BatchWriteSubmitted":
            digest = event.get("digest")
            if digest:
                state = batch_for(batches, digest)
                if state.write_submitted_at is None:
                    state.write_submitted_at = ts_ms
                state.size_bytes = max(state.size_bytes, int(event.get("batch_size_bytes", 0)))

        elif name == "PayloadMarkerWriteSubmitted":
            digest = event.get("digest")
            if digest:
                state = batch_for(batches, digest)
                if state.marker_submitted_at is None:
                    state.marker_submitted_at = ts_ms

        elif name == "PayloadReferenced":
            digest = event.get("digest")
            header = event.get("header_digest") or event.get("related_header_digest") or ""
            if digest:
                state = batch_for(batches, digest)
                if header and header not in state.references:
                    state.references[header] = ts_ms
                if state.first_referenced_at is None or ts_ms < state.first_referenced_at:
                    state.first_referenced_at = ts_ms
                    if "round" in event:
                        state.first_referenced_round = int(event["round"])

        elif name == "CertificateCommitted":
            payloads = list(event.get("payload_digests", []))
            record = CommitRecord(
                ts_ms=ts_ms,
                certificate_digest=str(event.get("certificate_digest", "")),
                round=int(event.get("round", 0)),
                payload_digests=payloads,
            )
            commits.append(record)
            for digest in payloads:
                state = batch_for(batches, digest)
                if state.committed_at is None or ts_ms < state.committed_at:
                    state.committed_at = ts_ms
                    state.committed_round = record.round

        elif name == "CleanupAdvanced":
            cleanup_events.append(event)

        elif name == "RepairWaiterAdded":
            key = repair_key(event)
            record = RepairRecord(
                key=key,
                reason=str(event.get("reason", "")),
                missing_digest=str(event.get("missing_digest", "")),
                added_at=ts_ms,
            )
            active_repairs.setdefault(key, []).append(record)
            repair_records.append(record)

        elif name == "RepairWaiterRetried":
            key = repair_key(event)
            candidates = active_repairs.get(key, [])
            if candidates:
                candidates[-1].retry_count += 1
                continue

            missing_digest = str(event.get("missing_digest", ""))
            reason = str(event.get("reason", ""))
            for candidate_key, records in active_repairs.items():
                if candidate_key[2] == reason and candidate_key[3] == missing_digest and records:
                    records[-1].retry_count += 1
                    break

        elif name == "RepairWaiterCleared":
            key = repair_key(event)
            record = pop_active(active_repairs, key, event)
            if record:
                record.cleared_at = ts_ms
                record.clear_reason = str(event.get("clear_reason", ""))

    return batches, commits, cleanup_events, repair_records


def pop_active(active: Dict[Tuple[str, str, str, str, str, str], List[RepairRecord]], key, event) -> Optional[RepairRecord]:
    exact = active.get(key)
    if exact:
        return exact.pop(0)

    reason = str(event.get("reason", ""))
    missing = str(event.get("missing_digest", ""))
    certificate = str(event.get("certificate_digest", ""))
    for candidate_key, records in active.items():
        if not records:
            continue
        same_reason = candidate_key[2] == reason
        same_missing = missing and candidate_key[3] == missing
        same_certificate = certificate and candidate_key[5] == certificate
        if same_reason and (same_missing or same_certificate):
            return records.pop(0)
    return None


def apply_mock_execution(commits: List[CommitRecord], args) -> None:
    for record in commits:
        executed = record.ts_ms + args.execution_delay_ms
        if args.execution == "bursty":
            executed = apply_bursty_pause(executed, args.bursty_period_ms, args.bursty_pause_ms)
        record.executed_at = executed

    if args.checkpoint_every > 0:
        for start in range(0, len(commits), args.checkpoint_every):
            group = commits[start : start + args.checkpoint_every]
            covered_at = max(x.executed_at or x.ts_ms for x in group)
            for record in group:
                record.checkpointed_at = covered_at
    elif args.checkpoint_interval_ms > 0:
        first_ts = min((x.ts_ms for x in commits), default=0)
        for record in commits:
            executed = record.executed_at or record.ts_ms
            delta = max(0, executed - first_ts)
            slots = int(math.ceil(delta / args.checkpoint_interval_ms))
            record.checkpointed_at = first_ts + slots * args.checkpoint_interval_ms


def apply_bursty_pause(ts_ms: int, period_ms: int, pause_ms: int) -> int:
    if period_ms <= 0 or pause_ms <= 0:
        return ts_ms
    offset = ts_ms % period_ms
    if offset < pause_ms:
        return ts_ms + (pause_ms - offset)
    return ts_ms


def propagate_mock_times(batches: Dict[str, BatchState], commits: List[CommitRecord]) -> None:
    for record in commits:
        for digest in record.payload_digests:
            state = batch_for(batches, digest)
            if record.executed_at is not None and (
                state.executed_at is None or record.executed_at < state.executed_at
            ):
                state.executed_at = record.executed_at
            if record.checkpointed_at is not None and (
                state.checkpointed_at is None or record.checkpointed_at < state.checkpointed_at
            ):
                state.checkpointed_at = record.checkpointed_at


def percentile(values: List[int], pct: float) -> Optional[float]:
    if not values:
        return None
    values = sorted(values)
    index = (len(values) - 1) * pct
    lower = int(math.floor(index))
    upper = int(math.ceil(index))
    if lower == upper:
        return float(values[lower])
    return values[lower] * (upper - index) + values[upper] * (index - lower)


def latency_summary(values: List[int]) -> dict:
    return {
        "count": len(values),
        "p50_ms": percentile(values, 0.50),
        "p95_ms": percentile(values, 0.95),
        "p99_ms": percentile(values, 0.99),
        "max_ms": max(values) if values else None,
    }


def write_lifecycle_latencies(out_dir: Path, batches: Dict[str, BatchState]) -> dict:
    rows = []
    stored_ref = []
    ref_commit = []
    commit_exec = []
    exec_checkpoint = []

    for state in sorted(batches.values(), key=lambda x: x.digest):
        row = {
            "digest": state.digest,
            "size_bytes": state.size_bytes,
            "write_submitted_at": state.write_submitted_at,
            "marker_submitted_at": state.marker_submitted_at,
            "first_referenced_at": state.first_referenced_at,
            "first_referenced_round": state.first_referenced_round,
            "committed_at": state.committed_at,
            "committed_round": state.committed_round,
            "mock_executed_at": state.executed_at,
            "mock_checkpointed_at": state.checkpointed_at,
            "write_to_reference_ms": delta(state.write_submitted_at, state.first_referenced_at),
            "reference_to_commit_ms": delta(state.first_referenced_at, state.committed_at),
            "commit_to_mock_execute_ms": delta(state.committed_at, state.executed_at),
            "mock_execute_to_checkpoint_ms": delta(state.executed_at, state.checkpointed_at),
        }
        rows.append(row)
        append_if_not_none(stored_ref, row["write_to_reference_ms"])
        append_if_not_none(ref_commit, row["reference_to_commit_ms"])
        append_if_not_none(commit_exec, row["commit_to_mock_execute_ms"])
        append_if_not_none(exec_checkpoint, row["mock_execute_to_checkpoint_ms"])

    write_csv(out_dir / "lifecycle_latencies.csv", rows)
    return {
        "write_to_reference": latency_summary(stored_ref),
        "reference_to_commit": latency_summary(ref_commit),
        "commit_to_mock_execute": latency_summary(commit_exec),
        "mock_execute_to_checkpoint": latency_summary(exec_checkpoint),
    }


def delta(start: Optional[int], end: Optional[int]) -> Optional[int]:
    if start is None or end is None:
        return None
    return end - start


def append_if_not_none(values: List[int], value: Optional[int]) -> None:
    if value is not None:
        values.append(value)


def write_frontiers(out_dir: Path, events: List[dict], commits: List[CommitRecord], cleanup_events: List[dict], repairs: List[RepairRecord]) -> None:
    times = {int(x.get("ts_ms", 0)) for x in events}
    times.update(x.executed_at for x in commits if x.executed_at is not None)
    times.update(x.checkpointed_at for x in commits if x.checkpointed_at is not None)
    rows = []

    for ts in sorted(times):
        commit_round = max((x.round for x in commits if x.ts_ms <= ts), default=0)
        execution_round = max((x.round for x in commits if x.executed_at is not None and x.executed_at <= ts), default=0)
        checkpoint_round = max(
            (x.round for x in commits if x.checkpointed_at is not None and x.checkpointed_at <= ts),
            default=0,
        )
        cleanup_round = max(
            (
                int(x.get("cleanup_round", 0))
                for x in cleanup_events
                if int(x.get("ts_ms", 0)) <= ts
            ),
            default=0,
        )
        active_repairs = sum(
            1
            for x in repairs
            if x.added_at <= ts and (x.cleared_at is None or ts < x.cleared_at)
        )
        rows.append(
            {
                "ts_ms": ts,
                "commit_round": commit_round,
                "cleanup_round": cleanup_round,
                "mock_execution_round": execution_round,
                "mock_checkpoint_round": checkpoint_round,
                "active_repair_waiters": active_repairs,
            }
        )

    write_csv(out_dir / "frontier_timeseries.csv", rows)


def write_mismatch(out_dir: Path, batches: Dict[str, BatchState], cleanup_events: List[dict], repairs: List[RepairRecord]) -> None:
    rows = []
    for event in cleanup_events:
        ts_ms = int(event.get("ts_ms", 0))
        cleanup_round = int(event.get("cleanup_round", 0))
        old_live_count = 0
        old_live_bytes = 0
        no_obligation_retained_count = 0
        no_obligation_retained_bytes = 0
        why_counts: Dict[str, int] = {}

        for state in batches.values():
            ref_round = state.first_referenced_round
            if ref_round is None:
                continue
            old_by_round = ref_round <= cleanup_round
            retained_by_round_window = ref_round > cleanup_round
            why = why_live_at(state, ts_ms, repairs)
            live = why != "not_live"
            if live:
                why_counts[why] = why_counts.get(why, 0) + 1
            if old_by_round and live:
                old_live_count += 1
                old_live_bytes += state.size_bytes
            if retained_by_round_window and not live:
                no_obligation_retained_count += 1
                no_obligation_retained_bytes += state.size_bytes

        row = {
            "ts_ms": ts_ms,
            "source": event.get("source", ""),
            "committed_round": event.get("committed_round", ""),
            "cleanup_round": cleanup_round,
            "gc_depth": event.get("gc_depth", ""),
            "old_by_round_but_live_count": old_live_count,
            "old_by_round_but_live_bytes": old_live_bytes,
            "no_local_obligation_but_retained_count": no_obligation_retained_count,
            "no_local_obligation_but_retained_bytes": no_obligation_retained_bytes,
        }
        row.update({f"why_{k}": v for k, v in sorted(why_counts.items())})
        rows.append(row)

    write_csv(out_dir / "round_policy_mismatch.csv", rows)


def why_live_at(state: BatchState, ts_ms: int, repairs: List[RepairRecord]) -> str:
    for repair in repairs:
        if repair.reason not in ("missing_batch", "worker_sync"):
            continue
        if repair.missing_digest != state.digest:
            continue
        if repair.added_at <= ts_ms and (repair.cleared_at is None or ts_ms < repair.cleared_at):
            return "repair_waiter_active"
    if state.committed_at is not None and state.committed_at <= ts_ms:
        if state.executed_at is None or ts_ms < state.executed_at:
            return "committed_not_executed"
        if state.checkpointed_at is None or ts_ms < state.checkpointed_at:
            return "checkpoint_pending"
        return "not_live"
    if state.first_referenced_at is not None and state.first_referenced_at <= ts_ms:
        return "referenced_not_committed_or_unknown"
    return "unknown_or_insufficient_trace"


def write_repair_lifetimes(out_dir: Path, repairs: List[RepairRecord]) -> dict:
    rows = []
    lifetimes = []
    for repair in repairs:
        lifetime = delta(repair.added_at, repair.cleared_at)
        append_if_not_none(lifetimes, lifetime)
        rows.append(
            {
                "reason": repair.reason,
                "missing_digest": repair.missing_digest,
                "added_at": repair.added_at,
                "cleared_at": repair.cleared_at,
                "lifetime_ms": lifetime,
                "clear_reason": repair.clear_reason,
                "retry_count": repair.retry_count,
            }
        )
    write_csv(out_dir / "repair_waiters.csv", rows)
    return {
        "lifetimes": latency_summary(lifetimes),
        "total_retries": sum(x.retry_count for x in repairs),
        "active_at_end": sum(1 for x in repairs if x.cleared_at is None),
    }


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


def maybe_write_plots(out_dir: Path) -> None:
    try:
        import matplotlib.pyplot as plt
    except Exception:
        return

    latency_file = out_dir / "lifecycle_latencies.csv"
    if latency_file.exists() and latency_file.stat().st_size > 0:
        with latency_file.open("r", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        for field in (
            "write_to_reference_ms",
            "reference_to_commit_ms",
            "commit_to_mock_execute_ms",
            "mock_execute_to_checkpoint_ms",
        ):
            values = sorted(int(row[field]) for row in rows if row.get(field))
            if not values:
                continue
            y = [(i + 1) / len(values) for i in range(len(values))]
            plt.plot(values, y, label=field)
        plt.xlabel("latency (ms)")
        plt.ylabel("CDF")
        plt.legend()
        plt.tight_layout()
        plt.savefig(out_dir / "lifecycle_latency_cdf.png")
        plt.close()

    frontier_file = out_dir / "frontier_timeseries.csv"
    if frontier_file.exists() and frontier_file.stat().st_size > 0:
        with frontier_file.open("r", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        if rows:
            base = int(rows[0]["ts_ms"])
            xs = [(int(row["ts_ms"]) - base) / 1000.0 for row in rows]
            for field in ("commit_round", "cleanup_round", "mock_execution_round", "mock_checkpoint_round"):
                plt.plot(xs, [int(row[field]) for row in rows], label=field)
            plt.xlabel("time since first event (s)")
            plt.ylabel("round")
            plt.legend()
            plt.tight_layout()
            plt.savefig(out_dir / "frontier_skew.png")
            plt.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", nargs="+", required=True, type=Path, help="JSONL trace files")
    parser.add_argument("--out-dir", required=True, type=Path, help="Directory for CSV/JSON outputs")
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
    parser.add_argument("--plots", action="store_true", help="Write PNG plots if matplotlib is installed")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.execution == "slow" and args.execution_delay_ms == 1000:
        args.execution_delay_ms = 30000

    args.out_dir.mkdir(parents=True, exist_ok=True)
    events = read_events(args.trace)
    batches, commits, cleanup_events, repairs = replay(events)
    apply_mock_execution(commits, args)
    propagate_mock_times(batches, commits)

    latency = write_lifecycle_latencies(args.out_dir, batches)
    write_frontiers(args.out_dir, events, commits, cleanup_events, repairs)
    write_mismatch(args.out_dir, batches, cleanup_events, repairs)
    repair_summary = write_repair_lifetimes(args.out_dir, repairs)

    summary = {
        "input_files": [str(x) for x in args.trace],
        "event_count": len(events),
        "batch_count": len(batches),
        "commit_count": len(commits),
        "cleanup_event_count": len(cleanup_events),
        "repair_waiter_count": len(repairs),
        "latency": latency,
        "repair": repair_summary,
        "interpretation": (
            "This is a derived shadow view over passive traces. It compares a hypothetical "
            "round/gc_depth payload lifecycle policy with local obligations; it is not evidence "
            "that the Narwhal baseline physically deletes payloads."
        ),
    }
    (args.out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    if args.plots:
        maybe_write_plots(args.out_dir)


if __name__ == "__main__":
    main()
