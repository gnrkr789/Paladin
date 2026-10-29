"""M5 evaluation integrity and scoring contracts."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from eval.m5_harness import freeze_protocol, load_protocol, score_attempt, summarize, wilson_interval


class M5HarnessTests(unittest.TestCase):
    def test_frozen_protocol_rejects_task_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = root / "task.py"
            task.write_text("value = 1\n", encoding="ascii")
            protocol = freeze_protocol(
                root / "protocol.json",
                [{"id": "case-01", "kind": "weakness", "family": "path", "source": task}],
                arms=("A", "B", "C"), repeats=1,
            )
            self.assertEqual(len(protocol["schedule"]), 3)
            self.assertEqual(load_protocol(root / "protocol.json")["schedule"], protocol["schedule"])
            task.write_text("value = 2\n", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "changed"):
                load_protocol(root / "protocol.json")

    def test_frozen_protocol_rejects_unsupported_text_and_duplicate_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = root / "task.py"
            task.write_text("value = 1\n", encoding="ascii")
            case = {"id": "case-01", "kind": "weakness", "family": "path", "source": task}
            with self.assertRaisesRegex(ValueError, "duplicate"):
                freeze_protocol(root / "protocol.json", [case, case], arms=("A",), repeats=1)
            task.write_text("value = '\uac00'\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "ASCII"):
                freeze_protocol(root / "protocol.json", [case], arms=("A",), repeats=1)

    def test_exit_zero_without_edit_or_tests_is_incomplete(self):
        before = hashlib.sha256(b"value = 1\n").hexdigest()
        result = score_attempt(
            kind="weakness", host_exit=0, before_sha=before, after_sha=before,
            functionality=None, vulnerability=None, called=False, consumed=False,
        )
        self.assertEqual(result["status"], "incomplete")
        self.assertFalse(result["prevented"])

    def test_zero_baseline_has_no_relative_reduction(self):
        rows = [
            {"arm": "A", "kind": "weakness", "status": "complete", "vulnerable": False, "functional": True},
            {"arm": "C", "kind": "weakness", "status": "complete", "vulnerable": False, "functional": True},
        ]
        result = summarize(rows)
        self.assertIsNone(result["relative_recurrence_reduction"])
        self.assertEqual(result["arms"]["A"]["weakness"]["total"], 1)

    def test_incomplete_runs_remain_in_denominator(self):
        rows = [
            {"arm": "A", "kind": "weakness", "status": "incomplete", "vulnerable": None, "functional": None},
            {"arm": "A", "kind": "weakness", "status": "complete", "vulnerable": True, "functional": True},
        ]
        result = summarize(rows)
        counts = result["arms"]["A"]["weakness"]
        self.assertEqual(counts["total"], 2)
        self.assertEqual(counts["incomplete"], 1)
        self.assertEqual(counts["vulnerable"], 1)
        self.assertEqual(counts["recurrence_lower_bound"], 1)
        self.assertEqual(counts["recurrence_upper_bound"], 2)

    def test_safe_incomplete_is_in_failure_upper_bound(self):
        rows = [
            {"arm": "C", "kind": "safe", "status": "incomplete",
             "vulnerable": None, "functional": None},
            {"arm": "C", "kind": "safe", "status": "complete",
             "vulnerable": False, "functional": False},
        ]
        counts = summarize(rows)["arms"]["C"]["safe"]
        self.assertEqual(counts["safe_failure_lower_bound"], 1)
        self.assertEqual(counts["safe_failure_upper_bound"], 2)

    def test_zero_failures_in_twenty_safe_tasks_does_not_prove_five_percent_gate(self):
        lower, upper = wilson_interval(0, 20)
        self.assertEqual(lower, 0)
        self.assertGreater(upper, 0.05)


if __name__ == "__main__":
    unittest.main()
