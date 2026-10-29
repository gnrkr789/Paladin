"""The replay verifier must reject reparse paths and retain launch errors."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.replay_guidance_worker_eval_v3 import capture_launch, strict_manifest


class GuidanceWorkerReplayV3Tests(unittest.TestCase):
    def test_root_junction_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "a.py").write_bytes(b"pass\n")
            with patch("os.path.isjunction", side_effect=lambda p: Path(p) == root):
                with self.assertRaises(ValueError):
                    strict_manifest(root)

    def test_launch_error_is_captured(self):
        with patch("subprocess.run", side_effect=FileNotFoundError("python missing")):
            captured = capture_launch(["missing-python", "probe.py"], Path("."), {})
        self.assertIsNone(captured["exit_code"])
        self.assertEqual(captured["launch_error"], "FileNotFoundError: python missing")
        self.assertEqual(captured["stderr"], b"")


if __name__ == "__main__":
    unittest.main()
