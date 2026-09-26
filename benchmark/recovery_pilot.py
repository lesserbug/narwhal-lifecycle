"""Run one local ordering pilot with an optional bounded worker pause (Linux/WSL)."""

import argparse
import hashlib
import json
import os
import signal
import subprocess
import time
from math import ceil
from pathlib import Path

from benchmark.config import Key, LocalCommittee, NodeParameters


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "target/release"
PARAMETERS = {
    "header_size": 1_000,
    "max_header_delay": 200,
    "gc_depth": 50,
    "sync_retry_delay": 10_000,
    "sync_retry_nodes": 3,
    "batch_size": 500_000,
    "max_batch_delay": 200,
}


def now_ms():
    return time.time_ns() // 1_000_000


def output_count(path):
    if not path.exists():
        return 0
    with path.open(encoding="utf-8") as stream:
        return sum('"event":"CertificateCommitted"' in line for line in stream)


def process_state(pid):
    with Path(f"/proc/{pid}/status").open(encoding="utf-8") as stream:
        return next(line.split()[1] for line in stream if line.startswith("State:"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--fault-seconds", type=int, default=0,
                        help="0 = clean P0; positive = pause worker-0-0 once")
    parser.add_argument("--rate", type=int, default=25_000)
    parser.add_argument("--warmup-seconds", type=int, default=30)
    parser.add_argument("--observe-seconds", type=int, default=300)
    args = parser.parse_args()
    if args.fault_seconds < 0 or args.rate <= 0 or args.warmup_seconds < 30 or args.observe_seconds <= 0:
        parser.error("fault >= 0, rate > 0, warmup >= 30, and observation > 0 are required")
    if not (BIN / "node").is_file() or not (BIN / "benchmark_client").is_file():
        parser.error("build first: cargo build --release -p node --features benchmark")

    out = args.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=False)
    traces = out / "lifecycle"
    traces.mkdir()
    logs = out / "logs"
    logs.mkdir()
    keys = []
    for i in range(4):
        key_file = out / f".node-{i}.json"
        subprocess.run([str(BIN / "node"), "generate_keys", "--filename", str(key_file)], check=True)
        keys.append(Key.from_file(str(key_file)))
    committee = LocalCommittee([key.name for key in keys], 5000, 1)
    committee_file = out / "committee.json"
    committee.print(str(committee_file))
    parameters_file = out / "parameters.json"
    NodeParameters(PARAMETERS).print(str(parameters_file))

    config_hash = hashlib.sha256(committee_file.read_bytes() + parameters_file.read_bytes()).hexdigest()
    metadata = {
        "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "git_status": subprocess.check_output(["git", "status", "--short"], cwd=ROOT, text=True).strip(),
        "config_hash": config_hash,
        "topology": "4 primaries, 1 worker per primary, localhost",
        "target_role": "worker",
        "target_id": "worker-0-0",
        "target_ordering_primary": "primary-0",
        "reference_ordering_primary": "primary-1",
        "workload": {"rate_tx_s": args.rate, "tx_size_bytes": 512, "client_seed": None},
        "data_seed": "fresh empty stores",
        "fault_mode": "SIGSTOP/SIGCONT" if args.fault_seconds else "none",
        "fault_duration_seconds": args.fault_seconds,
        "warmup_seconds": args.warmup_seconds,
        "observation_limit_seconds": args.observe_seconds,
        "recovery_rule": None,
        "trace_mode": "on",
        "processes": {},
        "status": "incomplete",
    }
    metadata_file = out / "run.json"

    def save_metadata():
        metadata_file.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    processes = []
    log_streams = []
    paused = False
    target_worker = None
    events_file = out / "fault-events.jsonl"
    save_metadata()

    def launch(name, command, trace=None):
        env = os.environ.copy()
        if trace:
            env["NARWHAL_LIFECYCLE_TRACE"] = str(traces / f"{name}.jsonl")
        else:
            env.pop("NARWHAL_LIFECYCLE_TRACE", None)
        stream = (logs / f"{name}.log").open("w", encoding="utf-8")
        log_streams.append(stream)
        proc = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=stream, env=env)
        processes.append((name, proc))
        metadata["processes"][name] = proc.pid
        save_metadata()
        return proc

    def check_alive():
        for name, proc in processes:
            if proc.poll() is not None:
                raise RuntimeError(f"{name} exited with code {proc.returncode}; see {logs / (name + '.log')}")

    def wait_for(predicate, timeout, description):
        deadline = time.monotonic() + timeout
        while not predicate():
            check_alive()
            if time.monotonic() >= deadline:
                raise RuntimeError(f"timed out waiting for {description}")
            time.sleep(0.5)

    def sleep_checked(seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            check_alive()
            time.sleep(min(1, deadline - time.monotonic()))

    def record(event, **fields):
        with events_file.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"event": event, "ts_ms": now_ms(),
                                     "monotonic_ns": time.monotonic_ns(), **fields}) + "\n")

    try:
        for i in range(4):
            common = [str(BIN / "node"), "-vv", "run", "--keys", str(out / f".node-{i}.json"),
                      "--committee", str(committee_file), "--parameters", str(parameters_file)]
            launch(f"primary-{i}", common + ["--store", str(out / f"db-primary-{i}"), "primary"], trace=True)
            worker = launch(f"worker-{i}-0", common + ["--store", str(out / f"db-worker-{i}-0"),
                                                    "worker", "--id", "0"], trace=True)
            if i == 0:
                target_worker = worker

        addresses = [address for group in committee.workers_addresses() for _, address in group]
        for i, address in enumerate(addresses):
            launch(f"client-{i}-0", [str(BIN / "benchmark_client"), address, "--size", "512",
                                     "--rate", str(ceil(args.rate / 4)), "--nodes", *addresses])

        target_trace = traces / "primary-0.jsonl"
        reference_trace = traces / "primary-1.jsonl"
        wait_for(lambda: all("Start sending transactions" in (logs / f"client-{i}-0.log").read_text()
                             for i in range(4)), 60, "all clients to start")
        wait_for(lambda: output_count(target_trace) > 0 and output_count(reference_trace) > 0,
                 60, "target and reference ordering outputs")
        before = (output_count(target_trace), output_count(reference_trace))
        sleep_checked(args.warmup_seconds)
        after = (output_count(target_trace), output_count(reference_trace))
        if after[0] <= before[0] or after[1] <= before[1]:
            raise RuntimeError(f"ordering did not advance throughout warmup: {before} -> {after}")
        record("WarmupCompleted", target_outputs=after[0], reference_outputs=after[1])

        if args.fault_seconds:
            try:
                paused = True
                signal_sent_ms = now_ms()
                os.kill(target_worker.pid, signal.SIGSTOP)
                wait_for(lambda: process_state(target_worker.pid) == "T", 2, "target to stop")
                record("FaultStarted", target_pid=target_worker.pid,
                       signal_sent_ms=signal_sent_ms, process_state=process_state(target_worker.pid))
                sleep_checked(args.fault_seconds)
            finally:
                if paused:
                    signal_sent_ms = now_ms()
                    os.kill(target_worker.pid, signal.SIGCONT)
                    paused = False
                    wait_for(lambda: target_worker.poll() is None and process_state(target_worker.pid) != "T",
                             2, "target to resume")
                    record("FaultEnded", target_pid=target_worker.pid,
                           signal_sent_ms=signal_sent_ms, process_state=process_state(target_worker.pid))
        sleep_checked(args.observe_seconds)
        record("ObservationEnded", target_outputs=output_count(target_trace),
               reference_outputs=output_count(reference_trace))
        metadata["status"] = "completed"
    finally:
        if paused and target_worker is not None and target_worker.poll() is None:
            os.kill(target_worker.pid, signal.SIGCONT)
            record("FaultEnded", target_pid=target_worker.pid,
                   process_state=process_state(target_worker.pid), reason="interrupted")
        metadata["ended_ms"] = now_ms()
        save_metadata()
        for _, proc in reversed(processes):
            if proc.poll() is None:
                proc.terminate()
        for _, proc in reversed(processes):
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        for stream in log_streams:
            stream.close()
    print(f"Pilot artifacts: {out}")


if __name__ == "__main__":
    main()
