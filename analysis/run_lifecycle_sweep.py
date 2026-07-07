#!/usr/bin/env python3
"""Run an offline lifecycle parameter sweep over existing Narwhal traces."""

import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List


DEFAULT_EXECUTION_DELAYS_MS = (0, 1000, 5000, 10000, 30000, 60000)
DEFAULT_POLICY_GC_DEPTHS = (10, 25, 50, 100)
DEFAULT_CHECKPOINT_EVERY = (10, 50, 100, 0)

OLD_LIVE_REASON_BYTE_FIELDS = (
    "old_live_why_committed_not_executed_bytes",
    "old_live_why_checkpoint_pending_bytes",
    "old_live_why_repair_waiter_active_bytes",
    "old_live_why_referenced_not_committed_or_unknown_bytes",
    "old_live_why_unknown_or_insufficient_trace_bytes",
)

RETAINED_DEAD_REASON_BYTE_FIELDS = (
    "retained_dead_why_executed_and_checkpointed_bytes",
    "retained_dead_why_no_obligation_bytes",
    "retained_dead_why_unknown_bytes",
)


def parse_int_list(value: str) -> List[int]:
    result = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        if item.lower() == "none":
            result.append(0)
        else:
            result.append(int(item))
    return result


def read_csv_rows(path: Path) -> List[dict]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open("r", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def int_field(row: dict, field: str) -> int:
    value = row.get(field, "")
    if value in ("", None):
        return 0
    return int(float(value))


def max_field(rows: Iterable[dict], field: str) -> int:
    return max((int_field(row, field) for row in rows), default=0)


def checkpoint_label(checkpoint_every: int) -> str:
    return "none" if checkpoint_every == 0 else str(checkpoint_every)


def run_shadow_analysis(args, run_dir: Path, delay_ms: int, gc_depth: int, checkpoint_every: int) -> None:
    script = Path(__file__).with_name("shadow_lifecycle.py")
    cmd = [
        sys.executable,
        str(script),
        "--trace",
        *[str(path) for path in args.trace],
        "--out-dir",
        str(run_dir),
        "--execution",
        "fast",
        "--execution-delay-ms",
        str(delay_ms),
        "--checkpoint-every",
        str(checkpoint_every),
        "--policy-gc-depth",
        str(gc_depth),
    ]
    subprocess.run(cmd, check=True)


def summarize_run(run_dir: Path, delay_ms: int, gc_depth: int, checkpoint_every: int) -> dict:
    mismatch_rows = read_csv_rows(run_dir / "round_policy_mismatch.csv")
    summary = read_json(run_dir / "summary.json")
    last = mismatch_rows[-1] if mismatch_rows else {}

    row = {
        "execution_delay_ms": delay_ms,
        "policy_gc_depth": gc_depth,
        "checkpoint_every": checkpoint_label(checkpoint_every),
        "run_dir": str(run_dir),
        "event_count": summary.get("event_count", 0),
        "batch_count": summary.get("batch_count", 0),
        "commit_count": summary.get("commit_count", 0),
        "cleanup_event_count": summary.get("cleanup_event_count", 0),
        "policy_cleanup_runtime_fallback_count": summary.get("policy_cleanup_runtime_fallback_count", 0),
        "last_ts_ms": last.get("ts_ms", ""),
        "last_committed_round": last.get("committed_round", ""),
        "last_policy_cleanup_round": last.get("policy_cleanup_round", last.get("cleanup_round", "")),
        "last_runtime_cleanup_round": last.get("runtime_cleanup_round", ""),
        "last_old_by_round_but_live_count": int_field(last, "old_by_round_but_live_count"),
        "last_old_by_round_but_live_bytes": int_field(last, "old_by_round_but_live_bytes"),
        "max_old_by_round_but_live_count": max_field(mismatch_rows, "old_by_round_but_live_count"),
        "max_old_by_round_but_live_bytes": max_field(mismatch_rows, "old_by_round_but_live_bytes"),
        "last_no_local_obligation_but_retained_count": int_field(last, "no_local_obligation_but_retained_count"),
        "last_no_local_obligation_but_retained_bytes": int_field(last, "no_local_obligation_but_retained_bytes"),
        "max_no_local_obligation_but_retained_count": max_field(
            mismatch_rows,
            "no_local_obligation_but_retained_count",
        ),
        "max_no_local_obligation_but_retained_bytes": max_field(
            mismatch_rows,
            "no_local_obligation_but_retained_bytes",
        ),
    }

    for field in OLD_LIVE_REASON_BYTE_FIELDS + RETAINED_DEAD_REASON_BYTE_FIELDS:
        row[f"last_{field}"] = int_field(last, field)
        row[f"max_{field}"] = max_field(mismatch_rows, field)

    return row


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
    parser.add_argument("--out-dir", required=True, type=Path, help="Directory for sweep outputs")
    parser.add_argument(
        "--execution-delays-ms",
        default=",".join(str(x) for x in DEFAULT_EXECUTION_DELAYS_MS),
        help="Comma-separated mock execution delays in ms",
    )
    parser.add_argument(
        "--policy-gc-depths",
        default=",".join(str(x) for x in DEFAULT_POLICY_GC_DEPTHS),
        help="Comma-separated hypothetical lifecycle gc_depth values",
    )
    parser.add_argument(
        "--checkpoint-every",
        default=",".join(str(x) for x in DEFAULT_CHECKPOINT_EVERY),
        help="Comma-separated checkpoint group sizes; use 0 or none for no checkpoint coverage",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    execution_delays = parse_int_list(args.execution_delays_ms)
    gc_depths = parse_int_list(args.policy_gc_depths)
    checkpoint_values = parse_int_list(args.checkpoint_every)
    total = len(execution_delays) * len(gc_depths) * len(checkpoint_values)

    rows = []
    index = 0
    for delay_ms in execution_delays:
        for gc_depth in gc_depths:
            for checkpoint_every in checkpoint_values:
                index += 1
                run_name = f"delay-{delay_ms}_gc-{gc_depth}_checkpoint-{checkpoint_label(checkpoint_every)}"
                run_dir = args.out_dir / run_name
                print(f"[{index}/{total}] {run_name}", file=sys.stderr)
                run_shadow_analysis(args, run_dir, delay_ms, gc_depth, checkpoint_every)
                rows.append(summarize_run(run_dir, delay_ms, gc_depth, checkpoint_every))

    write_csv(args.out_dir / "sweep_summary.csv", rows)
    print(f"Wrote {args.out_dir / 'sweep_summary.csv'}")


if __name__ == "__main__":
    main()
