"""The final replay binds import neighbors and authenticates its prior freeze."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import replay_guidance_worker_eval_v5 as replay


class GuidanceWorkerReplayV5Tests(unittest.TestCase):
    def test_import_neighbor_changes_the_manifest(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "probe.py").write_bytes(b"pass\n")
            before = replay.strict_manifest(root)
            (root / "asyncio.py").write_bytes(b"raise RuntimeError()\n")
            self.assertNotEqual(before, replay.strict_manifest(root))

    def test_prior_freeze_is_checked_before_attempt(self):
        with patch.object(replay.prior, "digest", return_value="changed"):
            with self.assertRaisesRegex(ValueError, "earlier replay freeze changed"):
                replay.verify_attempt({"prior_freeze_sha256": "expected"}, "A-path_traversal")


if __name__ == "__main__":
    unittest.main()
