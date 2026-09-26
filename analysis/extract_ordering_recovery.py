"""Extract one Narwhal ordering target's clean progress and batch-read work."""

import argparse
import csv
import json
from bisect import bisect_right
from collections import Counter
from math import ceil
from pathlib import Path


def read_events(path):
    with path.open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def output_events(path):
    return [event for event in read_events(path)
            if event.get("event") == "CertificateCommitted"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace-dir", required=True, type=Path)
    parser.add_argument("--target", required=True, help="primary filename stem, e.g. primary-0")
    parser.add_argument("--reference", required=True, help="unaffected primary filename stem")
    parser.add_argument("--target-key-file", required=True, type=Path,
                        help="benchmark/.node-0.json for the target authority")
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()
    target_key = json.loads(args.target_key_file.read_text(encoding="utf-8"))["name"]

    target = output_events(args.trace_dir / f"{args.target}.jsonl")
    reference = output_events(args.trace_dir / f"{args.reference}.jsonl")
    if not target or not reference:
        parser.error("both primaries must have output events")

    target_ids = [event["certificate_digest"] for event in target]
    reference_ids = [event["certificate_digest"] for event in reference]
    if len(set(target_ids)) != len(target_ids) or len(set(reference_ids)) != len(reference_ids):
        parser.error("duplicate certificate output; progress is not comparable")
    common_length = min(len(target_ids), len(reference_ids))
    if target_ids[:common_length] != reference_ids[:common_length]:
        parser.error("certificate output sequences diverge; progress is not comparable")

    args.out_dir.mkdir(parents=True, exist_ok=False)
    target_times = sorted(event["ts_ms"] for event in target)
    reference_times = sorted(event["ts_ms"] for event in reference)
    start = min(target_times[0], reference_times[0]) // 1000 * 1000
    end = max(target_times[-1], reference_times[-1]) // 1000 * 1000 + 1000
    lags = []
    with (args.out_dir / "progress.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["sample_ts_ms", "reference", "target", "reference_outputs",
                         "target_outputs", "ordering_lag"])
        for sample in range(start, end + 1, 1000):
            ref_count = bisect_right(reference_times, sample)
            target_count = bisect_right(target_times, sample)
            lag = ref_count - target_count
            lags.append(lag)
            writer.writerow([sample, args.reference, args.target, ref_count, target_count, lag])

    attempts = []
    retries = 0
    waiter_added = 0
    waiter_resolved = 0
    waiter_cancelled = 0
    unmatched_clears = 0
    unmatched_retries = 0
    waiter_state = {}
    target_workers = args.target.replace("primary-", "worker-", 1) + "-"
    for path in sorted(args.trace_dir.glob("worker-*.jsonl")):
        for event in read_events(path):
            name = event.get("event")
            if name in {"BatchReadCompleted", "BatchReadMissing"} and event["requester"] == target_key:
                attempts.append((path.stem, event))
            elif path.stem.startswith(target_workers) and event.get("reason") == "worker_sync":
                key = (path.stem, event.get("missing_digest"))
                if name == "RepairWaiterAdded":
                    waiter_added += 1
                    waiter_state[key] = "active"
                elif name == "RepairWaiterCleared":
                    if waiter_state.get(key) == "active":
                        if event.get("clear_reason") == "resolved":
                            waiter_resolved += 1
                        elif event.get("clear_reason") == "cleanup_cancelled":
                            waiter_cancelled += 1
                        waiter_state[key] = event.get("clear_reason")
                    else:
                        unmatched_clears += 1
                elif name == "RepairWaiterRetried":
                    if waiter_state.get(key) == "active":
                        retries += 1
                    else:
                        unmatched_retries += 1

    repeats = Counter()
    with (args.out_dir / "attempts.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["attempt_id", "provider", "requester", "digest", "stage",
                         "result", "bytes_read", "repeat_index"])
        for provider, event in attempts:
            key = (provider, event["requester"], event["digest"])
            repeats[key] += 1
            success = event["event"] == "BatchReadCompleted"
            writer.writerow([f"{provider}:{event['seq']}", provider, event["requester"],
                             event["digest"], "provider_read", "success" if success else "missing",
                             event["batch_size_bytes"] if success else "", repeats[key]])

    summary = {
        "scope": "target ordering and provider reads; no fault or recovery-time claim",
        "target": args.target,
        "reference": args.reference,
        "target_outputs": len(target),
        "reference_outputs": len(reference),
        "ordering_lag_min": min(lags),
        "ordering_lag_max": max(lags),
        "ordering_lag_p95": sorted(lags)[ceil(0.95 * len(lags)) - 1],
        "target_provider_read_attempts": len(attempts),
        "target_provider_read_successes": sum(
            event["event"] == "BatchReadCompleted" for _, event in attempts),
        "target_provider_read_bytes": sum(
            event["batch_size_bytes"] for _, event in attempts
            if event["event"] == "BatchReadCompleted"),
        "repeated_provider_reads": sum(count - 1 for count in repeats.values()),
        "target_provider_missing_reads": sum(
            event["event"] == "BatchReadMissing" for _, event in attempts),
        "target_worker_sync_added": waiter_added,
        "target_worker_sync_retries": retries,
        "target_worker_sync_resolved": waiter_resolved,
        "target_worker_sync_unresolved": sum(value == "active" for value in waiter_state.values()),
        "target_worker_sync_cleanup_cancelled": waiter_cancelled,
        "target_worker_sync_unmatched_clears": unmatched_clears,
        "target_worker_sync_unmatched_retries": unmatched_retries,
    }
    (args.out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
