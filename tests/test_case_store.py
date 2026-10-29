import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from paladin.case_store import init_store, list_cases, promote_case


def valid_record():
    return {
        "candidate_id": "candidate-1", "cve_id": "CVE-2025-1234", "rule_id": "rule-1",
        "project_identity": "project-1", "before_sha256": "a" * 64,
        "after_sha256": "b" * 64, "verifier_id": "verifier-1", "evidence_sha256": "c" * 64,
        "before_risk_observed": True, "after_risk_blocked": True,
        "safe_before_passed": True, "safe_after_passed": True, "human_reviewed": False,
    }


class CaseStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "cases.sqlite"

    def test_persistence_idempotency_and_conflict(self):
        init_store(self.path)
        first = promote_case(self.path, valid_record())
        self.assertEqual(first, promote_case(self.path, valid_record()))
        self.assertEqual(list_cases(self.path), [first])
        conflict = {**valid_record(), "evidence_sha256": "d" * 64}
        with self.assertRaises(ValueError):
            promote_case(self.path, conflict)
        self.assertEqual(list_cases(self.path), [first])
        with closing(sqlite3.connect(self.path)) as db, db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("DELETE FROM verified_cases")

    def test_invalid_records_never_create_store(self):
        invalid = []
        missing = valid_record()
        del missing["evidence_sha256"]
        invalid.append(missing)
        invalid.append({**valid_record(), "safe_after_passed": False})
        invalid.append({**valid_record(), "safe_before_passed": 1})
        invalid.append({**valid_record(), "human_reviewed": True})
        invalid.append({**valid_record(), "before_sha256": "b" * 64})
        invalid.append({**valid_record(), "evidence_sha256": "G" * 64})
        invalid.append({**valid_record(), "candidate_id": "\uac00"})
        invalid.append({**valid_record(), "rule_id": "\x00"})
        invalid.append({**valid_record(), "extra": "value"})
        for record in invalid:
            with self.subTest(record=record), self.assertRaises(ValueError):
                promote_case(self.path, record)
            self.assertFalse(self.path.exists())

    def test_new_verifier_revision_does_not_overwrite_legacy_record(self):
        old = promote_case(self.path, valid_record())
        updated = {**valid_record(), "verifier_id": "verifier-2", "evidence_sha256": "e" * 64}
        new = promote_case(self.path, updated)
        self.assertNotEqual(old["case_id"], new["case_id"])
        self.assertEqual(new, promote_case(self.path, updated))
        self.assertEqual(len(list_cases(self.path)), 2)


if __name__ == "__main__":
    unittest.main()
