"""Replay evidence must bind bytes and preserve process failures."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.replay_guidance_worker_eval import capture_process, manifest_tree, verify_tree


class GuidanceWorkerReplayTests(unittest.TestCase):
    def test_manifest_rejects_changed_bytes_and_extra_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "source.py").write_bytes(b"original\n")
            expected = manifest_tree(root)
            verify_tree(root, expected)
            (root / "source.py").write_bytes(b"changed\n")
            with self.assertRaises(ValueError):
                verify_tree(root, expected)
            (root / "source.py").write_bytes(b"original\n")
            (root / "extra.py").write_bytes(b"unexpected\n")
            with self.assertRaises(ValueError):
                verify_tree(root, expected)

    def test_failed_process_keeps_exit_code_and_stderr(self):
        result = subprocess.CompletedProcess(["python", "probe.py"], 1, b"partial", b"traceback")
        with patch("subprocess.run", return_value=result):
            captured = capture_process(["python", "probe.py"], Path("."), {})
        self.assertEqual(captured["exit_code"], 1)
        self.assertEqual(captured["stdout"], b"partial")
        self.assertEqual(captured["stderr"], b"traceback")


if __name__ == "__main__":
    unittest.main()
