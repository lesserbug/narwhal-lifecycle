import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("extract_ordering_recovery.py")


def write_events(path, events):
    path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")


class ExtractOrderingRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.traces = self.root / "lifecycle"
        self.traces.mkdir()
        self.key_file = self.root / ".node-0.json"
        self.key_file.write_text('{"name":"target-key"}', encoding="utf-8")
        write_events(self.traces / "primary-0.jsonl", [
            {"event": "CertificateCommitted", "certificate_digest": "A", "ts_ms": 1000},
            {"event": "CertificateCommitted", "certificate_digest": "B", "ts_ms": 3000},
        ])
        write_events(self.traces / "primary-1.jsonl", [
            {"event": "CertificateCommitted", "certificate_digest": "A", "ts_ms": 1000},
            {"event": "CertificateCommitted", "certificate_digest": "B", "ts_ms": 2000},
        ])

    def extract(self):
        return subprocess.run([
            sys.executable, str(SCRIPT), "--trace-dir", str(self.traces),
            "--target", "primary-0", "--reference", "primary-1",
            "--target-key-file", str(self.key_file),
            "--out-dir", str(self.root / "result"),
        ], capture_output=True, text=True)

    def test_target_identity_and_repeated_provider_reads(self):
        write_events(self.traces / "worker-1-0.jsonl", [
            {"event": "BatchReadCompleted", "seq": 1, "requester": "target-key",
             "digest": "X", "batch_size_bytes": 10},
            {"event": "BatchReadCompleted", "seq": 2, "requester": "other-key",
             "digest": "X", "batch_size_bytes": 10},
            {"event": "BatchReadCompleted", "seq": 3, "requester": "target-key",
             "digest": "X", "batch_size_bytes": 10},
            {"event": "BatchReadMissing", "seq": 4, "requester": "target-key",
             "digest": "Y"},
        ])
        self.assertEqual(self.extract().returncode, 0)
        summary = json.loads((self.root / "result/summary.json").read_text())
        self.assertEqual(summary["target_provider_read_attempts"], 3)
        self.assertEqual(summary["target_provider_read_successes"], 2)
        self.assertEqual(summary["target_provider_missing_reads"], 1)
        self.assertEqual(summary["repeated_provider_reads"], 1)
        with (self.root / "result/attempts.csv").open(newline="") as stream:
            attempts = list(csv.DictReader(stream))
        self.assertEqual(attempts[-1]["result"], "missing")
        self.assertEqual(attempts[-1]["bytes_read"], "")
        with (self.root / "result/progress.csv").open(newline="") as stream:
            progress = list(csv.DictReader(stream))
        self.assertEqual(progress[1]["ordering_lag"], "1")

    def test_cleanup_cancellation_is_not_resolution(self):
        write_events(self.traces / "worker-0-0.jsonl", [
            {"event": "RepairWaiterCleared", "reason": "worker_sync",
             "missing_digest": "Z", "clear_reason": "resolved"},
            {"event": "RepairWaiterAdded", "reason": "worker_sync", "missing_digest": "X"},
            {"event": "RepairWaiterRetried", "reason": "worker_sync", "missing_digest": "X"},
            {"event": "RepairWaiterCleared", "reason": "worker_sync",
             "missing_digest": "X", "clear_reason": "cleanup_cancelled"},
            {"event": "RepairWaiterAdded", "reason": "worker_sync", "missing_digest": "Y"},
        ])
        self.assertEqual(self.extract().returncode, 0)
        summary = json.loads((self.root / "result/summary.json").read_text())
        self.assertEqual(summary["target_worker_sync_resolved"], 0)
        self.assertEqual(summary["target_worker_sync_cleanup_cancelled"], 1)
        self.assertEqual(summary["target_worker_sync_unresolved"], 1)
        self.assertEqual(summary["target_worker_sync_unmatched_clears"], 1)

    def test_divergent_output_rejects_progress(self):
        write_events(self.traces / "primary-1.jsonl", [
            {"event": "CertificateCommitted", "certificate_digest": "A", "ts_ms": 1000},
            {"event": "CertificateCommitted", "certificate_digest": "C", "ts_ms": 2000},
        ])
        result = self.extract()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("diverge", result.stderr)
        self.assertFalse((self.root / "result").exists())


if __name__ == "__main__":
    unittest.main()
