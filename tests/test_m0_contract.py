"""M0: evidence integrity and promotion boundaries; no PoC is executed."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "m0-corpus.schema.json"
VALIDATOR = ROOT / "scripts" / "validate_m0.py"


def validate(data):
    # A missing implementation yields a business-contract failure, not an
    # unrelated import/dependency failure during the first RED run.
    if not VALIDATOR.is_file():
        return ["validator_not_implemented"]
    spec = importlib.util.spec_from_file_location("m0_validator", VALIDATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.validate_dataset(data, root=ROOT, schema_path=SCHEMA)


class M0EvidenceContract(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "data/m0/cases.json").read_text(encoding="utf-8"))

    def assertError(self, prefix):
        errors = validate(self.data)
        self.assertTrue(any(e.startswith(prefix) for e in errors), errors)

    def test_observed_ten_case_corpus_is_valid_without_promoting_candidates(self):
        self.assertEqual(validate(self.data), [])

    def test_missing_preconditions_is_rejected(self):
        del self.data["cases"][0]["preconditions"]
        self.assertError("schema:")

    def test_duplicate_cve_does_not_count_as_two_independent_cases(self):
        self.data["cases"][1] = copy.deepcopy(self.data["cases"][0])
        self.assertError("duplicate_cve:")

    def test_cve_patch_mismatch_cannot_be_promoted_to_reviewed(self):
        self.data["cases"][4]["verification_status"] = "reviewed"
        self.assertError("patch_alignment_required:")

    def test_candidate_cannot_be_enabled_as_a_rule(self):
        self.data["cases"][0]["rule_enabled"] = True
        self.assertError("rule_verification_required:")

    def test_review_claim_needs_a_review_record(self):
        self.data["cases"][0]["verification_status"] = "reviewed"
        self.assertError("review_record_required:")

    def test_rejected_cve_cannot_be_promoted(self):
        self.data["cases"][0]["record_state"] = "REJECTED"
        self.data["cases"][0]["verification_status"] = "reviewed"
        self.assertError("published_record_required:")

    def test_tampered_source_snapshot_is_rejected(self):
        self.data["cases"][0]["evidence"][0]["sha256"] = "0" * 64
        self.assertError("snapshot_hash_mismatch:")

    def test_evidence_path_cannot_escape_the_workspace(self):
        self.data["cases"][0]["evidence"][0]["path"] = "../outside.json"
        self.assertError("evidence_path_outside_root:")

    def test_broken_patch_evidence_reference_is_rejected(self):
        self.data["cases"][0]["patch_anchor"]["evidence_id"] = "missing"
        self.assertError("patch_evidence_missing:")

    def test_patch_anchor_cannot_claim_lines_outside_snapshot(self):
        self.data["cases"][0]["patch_anchor"]["end_line"] = 10000000
        self.assertError("patch_anchor_out_of_range:")

    def test_no_automatic_sharing_in_m0(self):
        self.data["cases"][0]["contribution"]["sharing_enabled"] = True
        self.assertError("schema:")

    def test_m0_gate_needs_five_aligned_candidates_covering_all_families(self):
        for case in self.data["cases"]:
            if case["family"] == "ssrf":
                case["patch_alignment"] = "mismatch"
        self.assertError("m0_family_coverage:")


if __name__ == "__main__":
    unittest.main()
