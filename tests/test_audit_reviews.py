"""Audit and correction script: diff integrity and Codex failure reporting (plan: paladin-card-patch-review)."""
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import audit_reviews  # noqa: E402
from paladin import patch_review  # noqa: E402

DIFF = "diff --git a/pkg/mod.py b/pkg/mod.py\n--- a/pkg/mod.py\n+++ b/pkg/mod.py\n@@ -1 +1 @@\n+checked = True\n"
URL = "https://github.com/o/r/commit/abcdef1.diff"


class DiffIntegrityTests(unittest.TestCase):
    def test_a_diff_that_changed_since_the_review_is_refused(self):
        review = {"patches": [{"url": URL, "sha256": patch_review.sha256_text(DIFF)}]}

        with patch("audit_reviews.fetch", return_value=DIFF):
            self.assertEqual(audit_reviews.diffs_for(review)[0]["url"], URL)
        with patch("audit_reviews.fetch", return_value=DIFF + "+more\n"), self.assertRaisesRegex(ValueError, "changed"):
            audit_reviews.diffs_for(review)


class CodexFailureTests(unittest.TestCase):
    def test_a_failed_codex_call_reports_its_error_output(self):
        failed = subprocess.CompletedProcess([], 1, stdout="", stderr="... error: model gpt-x not found\n")

        with patch("audit_reviews.subprocess.run", return_value=failed), \
                self.assertRaisesRegex(RuntimeError, "model gpt-x not found"):
            audit_reviews.Asker("gpt-x").ask("prompt", audit_reviews.AUDIT_SCHEMA)


if __name__ == "__main__":
    unittest.main()
