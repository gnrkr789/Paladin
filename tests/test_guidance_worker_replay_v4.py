"""Final replay guards must reject changed roots and preserve launch errors."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import replay_guidance_worker_eval_v4 as replay


class GuidanceWorkerReplayV4Tests(unittest.TestCase):
    def test_parent_junction_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder)
            root = parent / "package"
            root.mkdir()
            (root / "a.py").write_bytes(b"pass\n")
            with patch("os.path.isjunction", side_effect=lambda p: Path(p) == parent,
                       create=True):
                with self.assertRaises(ValueError):
                    replay.strict_manifest(root)

    def test_launch_error_remains_a_recordable_result(self):
        with patch("subprocess.run", side_effect=PermissionError("denied")):
            result = replay.capture_launch(["python", "probe.py"], Path("."), {})
        self.assertIsNone(result["exit_code"])
        self.assertEqual(result["launch_error"], "PermissionError: denied")
        self.assertEqual(result["command"], ["python", "probe.py"])

    def test_malformed_output_and_missing_attempt_are_rejected(self):
        with self.assertRaises(ValueError):
            replay.decode_probe(b"[]")
        with self.assertRaises(ValueError):
            replay.validate_attempts([], ["A-case"])


if __name__ == "__main__":
    unittest.main()
