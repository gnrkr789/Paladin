"""The M5 synthetic tasks have meaningful starting states."""

from pathlib import Path
import tempfile
import unittest

from eval.m5_catalog import build_cases
from eval.m5_oracle import evaluate


class M5CatalogTests(unittest.TestCase):
    def test_forty_cases_cover_weakness_and_safe_tasks(self):
        with tempfile.TemporaryDirectory() as directory:
            cases = build_cases(Path(directory))
            self.assertEqual(len(cases), 40)
            self.assertEqual(sum(case["kind"] == "weakness" for case in cases), 20)
            self.assertEqual(sum(case["kind"] == "safe" for case in cases), 20)
            self.assertEqual(len({case["id"] for case in cases}), 40)
            for case in cases:
                outcome = evaluate(case["id"], case["source"])
                self.assertFalse(outcome["functional"], case["id"])
                self.assertEqual(outcome["vulnerable"], case["kind"] == "weakness", case["id"])


if __name__ == "__main__":
    unittest.main()
