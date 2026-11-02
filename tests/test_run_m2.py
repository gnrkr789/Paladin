"""The M2 runner never silently replaces a held-out measurement."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "eval"))

import run_m2  # noqa: E402


class HeldOutGuardTests(unittest.TestCase):
    def test_an_existing_held_out_result_is_not_overwritten_without_force(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "result.json"
            output.write_text("{}", encoding="utf-8")
            held_out = {"purpose": "known_item_retrieval_for_candidate_cards_first_run_is_held_out"}

            with self.assertRaises(SystemExit):
                run_m2.check_output(held_out, output, force=False)
            run_m2.check_output(held_out, output, force=True)
            run_m2.check_output({"purpose": "fixed_english_development_retrieval_check"}, output, force=False)
            run_m2.check_output(held_out, Path(folder) / "new.json", force=False)


if __name__ == "__main__":
    unittest.main()
