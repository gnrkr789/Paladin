"""Published CVE expansion data: attribution, pinned evidence and pack consistency (S6, S8)."""
import hashlib
import json
from pathlib import Path
import unittest

from paladin import knowledge

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "data" / "cve-expansion" / "sources"
LICENSES = {"CVE-": "licenses/CVE-Terms-of-Use.txt",
            "GHSA-": "licenses/github-advisory-database-CC-BY-4.0.txt",
            "PYSEC-": "licenses/pypa-advisory-database-CC-BY-4.0.txt"}


class ExpansionDataTests(unittest.TestCase):
    def test_every_copied_source_has_a_named_license_and_attribution(self):
        notice = (ROOT / "data" / "THIRD_PARTY.md").read_text(encoding="utf-8")

        self.assertIn("data/cve-expansion/sources/", notice)
        for prefix, license_path in LICENSES.items():
            self.assertTrue((ROOT / license_path).is_file(), license_path)
            self.assertIn(Path(license_path).name, notice)
        for path in SOURCES.iterdir():
            self.assertTrue(any(path.name.startswith(prefix) for prefix in LICENSES), path.name)

    def test_candidate_evidence_is_present_at_its_pinned_hash_and_nothing_else_is_shipped(self):
        pack = knowledge.load_pack()
        used = set()
        for pattern in pack["patterns"]:
            if pattern["verification_status"] != "candidate":
                continue
            for entry in pattern["evidence"]:
                path = ROOT / entry["snapshot_path"]
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), entry["sha256"], entry["snapshot_path"])
                used.add(path.name)
        self.assertEqual(used, {path.name for path in SOURCES.iterdir()})

    def test_cards_never_carry_code_blocks(self):
        for path in (ROOT / "data" / "cve-expansion" / "cards").glob("CVE-*.json"):
            card = json.loads(path.read_text(encoding="utf-8"))
            for field in ("cause", "prevention", "limitations"):
                self.assertNotIn("```", card[field], path.name)


if __name__ == "__main__":
    unittest.main()
