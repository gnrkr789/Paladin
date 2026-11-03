"""Pack v2: verified patterns kept, candidate cards added with pinned evidence copies (S5, S6)."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from paladin import knowledge, pack_build

PINS = {"pysec": "a" * 40, "ghsa": "b" * 40, "cvelist": "c" * 40}


def card(cve_id="CVE-2099-12345", family="xss"):
    return {"cve_id": cve_id, "family": family, "packages": ["jinja2"], "cwe_ids": ["CWE-79"],
            "status": "candidate", "drafter": "claude-sonnet-5-5",
            "title": "Attribute keys are not escaped", "cause": "The xmlattr filter accepted keys with spaces.",
            "preconditions": ["Untrusted keys reach xmlattr."], "prevention": "Reject keys with spaces.",
            "limitations": "Only the xmlattr filter is covered.",
            "fixtures": {"risk": "A key with a space injects an attribute.", "safe": "Plain keys render."},
            "citations": [{"source": cve_id, "quote": "accepts keys containing spaces"}],
            "fix_references": ["https://github.com/pallets/jinja/commit/716795349a41d4983a9a4771f7d883c96ea17be7"],
            "sources": [{"id": "GHSA-h5c8-rqwp-cp95", "path": "advisories/github-reviewed/2024/01/x/GHSA-h5c8-rqwp-cp95.json",
                         "sha256": None},
                        {"id": cve_id, "path": "cves/2099/12xxx/{}.json".format(cve_id), "sha256": None}]}


class PackBuildTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.tmp = Path(folder.name)
        self.roots = {name: self.tmp / name for name in PINS}
        self.card = card()
        for source in self.card["sources"]:
            root = self.roots["ghsa" if source["id"].startswith("GHSA") else "cvelist"]
            path = root / source["path"]
            path.parent.mkdir(parents=True)
            path.write_bytes(b'{"id": "%s"}' % source["id"].encode())
            source["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.dest = self.tmp / "repo"

    def test_evidence_copies_match_the_pinned_bytes_and_link_to_the_pinned_commit(self):
        evidence = pack_build.copy_evidence(self.card, self.roots, PINS, self.dest, "data/cve-expansion/sources")

        self.assertEqual([item["kind"] for item in evidence], ["advisory", "cve"])
        for item, source in zip(evidence, self.card["sources"]):
            self.assertEqual(item["sha256"], source["sha256"])
            self.assertEqual(hashlib.sha256((self.dest / item["snapshot_path"]).read_bytes()).hexdigest(),
                             source["sha256"])
        self.assertEqual(evidence[0]["url"], "https://github.com/github/advisory-database/blob/{}/{}".format(
            "b" * 40, self.card["sources"][0]["path"]))
        self.assertTrue(evidence[1]["url"].startswith("https://github.com/CVEProject/cvelistV5/blob/" + "c" * 40))

    def test_a_changed_source_is_refused(self):
        (self.roots["cvelist"] / self.card["sources"][1]["path"]).write_bytes(b"changed")

        with self.assertRaisesRegex(ValueError, "hash"):
            pack_build.copy_evidence(self.card, self.roots, PINS, self.dest, "data/cve-expansion/sources")

    def test_candidates_join_the_verified_patterns_and_the_pack_validates(self):
        base = knowledge.load_pack()
        evidence = pack_build.copy_evidence(self.card, self.roots, PINS, self.dest, "data/cve-expansion/sources")
        duplicate = card(base["patterns"][0]["cve_id"], base["patterns"][0]["family"])

        pack = pack_build.build_pack(base, [(self.card, evidence), (duplicate, evidence)], "2026-10-29")

        knowledge.validate_pack(pack)
        self.assertEqual(pack["pack_id"], "python-web-prevention-v2")
        self.assertEqual(len(pack["patterns"]), len(base["patterns"]) + 1)
        added = next(p for p in pack["patterns"] if p["cve_id"] == "CVE-2099-12345")
        self.assertEqual((added["verification_status"], added["source_review"]["reviewer"]),
                         ("candidate", "claude-sonnet-5-5"))
        self.assertEqual([f["role"] for f in added["fixtures"]], ["risk", "safe"])
        kept = next(p for p in pack["patterns"] if p["cve_id"] == duplicate["cve_id"])
        self.assertEqual(kept, base["patterns"][0])
        self.assertEqual(pack["patterns"][:len(base["patterns"])], base["patterns"])

    def test_a_patch_checked_review_promotes_the_card_and_applies_its_revision(self):
        base = knowledge.load_pack()
        evidence = pack_build.copy_evidence(self.card, self.roots, PINS, self.dest, "data/cve-expansion/sources")
        other = card("CVE-2099-12346")
        patches = [{"url": "https://github.com/pallets/jinja/commit/7167953.diff", "sha256": "d" * 64, "bytes": 900,
                    "truncated": False}]
        revised = {"cause": "Keys with spaces or slashes passed through.", "preconditions": ["Untrusted keys."],
                   "prevention": "Reject keys with spaces, slashes, equals signs or angle brackets.",
                   "limitations": "Values are escaped separately."}
        reviews = {self.card["cve_id"]: {"outcome": "patch_checked", "verdict": "misaligned", "revised": revised,
                                         "recheck": "aligned", "recheck_observation": "The fix rejects more characters.",
                                         "observation": "First look.", "patches": patches,
                                         "reviewer": "claude-sonnet-5-5", "date": "2026-11-03"},
                   other["cve_id"]: {"outcome": "candidate", "reason": "unrelated", "patches": patches}}

        pack = pack_build.build_pack(base, [(self.card, evidence), (other, evidence)], "2026-11-03", reviews)

        knowledge.validate_pack(pack)
        checked = next(p for p in pack["patterns"] if p["cve_id"] == self.card["cve_id"])
        self.assertEqual(checked["verification_status"], "patch_checked")
        self.assertEqual(checked["prevention"], revised["prevention"])
        self.assertEqual(checked["patch_review"], {"reviewer": "claude-sonnet-5-5", "date": "2026-11-03",
                                                   "observation": "The fix rejects more characters.",
                                                   "card_revised": True, "patches": patches})
        unchanged = next(p for p in pack["patterns"] if p["cve_id"] == other["cve_id"])
        self.assertEqual(unchanged["verification_status"], "candidate")
        self.assertNotIn("patch_review", unchanged)
        self.assertEqual(knowledge.verification_counts(pack)["patch_checked"],
                         knowledge.verification_counts(base).get("patch_checked", 0) + 1)

        unreviewed = copy.deepcopy(checked)
        del unreviewed["patch_review"]
        with self.assertRaises(ValueError):
            knowledge.validate_pack(dict(pack, patterns=pack["patterns"][:-2] + [unreviewed]))

    def test_cards_whose_cve_was_withdrawn_or_rejected_leave_the_pack_with_history(self):
        cards = [card("CVE-2099-0001"), card("CVE-2099-0002"), card("CVE-2099-0003"), card("CVE-2099-0004")]
        collection = {"cases": [{"cve_id": "CVE-2099-0001"}], "skipped_items": [
            {"advisory": "GHSA-a", "cve_id": "CVE-2099-0002", "reason": "cve_not_published"},
            {"advisory": "GHSA-b", "cve_id": "CVE-2099-0004", "reason": "withdrawn"}]}
        history = [{"cve_id": "CVE-2099-0009", "reason": "withdrawn", "date": "2026-01-01"}]

        active, withdrawn = pack_build.split_withdrawn(cards, collection, history, "2026-10-30")

        self.assertEqual([item["cve_id"] for item in active], ["CVE-2099-0001"])
        self.assertEqual(withdrawn, [
            {"cve_id": "CVE-2099-0002", "reason": "cve_not_published", "date": "2026-10-30"},
            {"cve_id": "CVE-2099-0003", "reason": "not_collected", "date": "2026-10-30"},
            {"cve_id": "CVE-2099-0004", "reason": "withdrawn", "date": "2026-10-30"},
            {"cve_id": "CVE-2099-0009", "reason": "withdrawn", "date": "2026-01-01"}])

    def test_withdrawal_history_keeps_the_first_date(self):
        history = [{"cve_id": "CVE-2099-0002", "reason": "not_collected", "date": "2026-01-01"}]

        _, withdrawn = pack_build.split_withdrawn([card("CVE-2099-0002")], {"cases": [], "skipped_items": []},
                                                  history, "2026-10-30")

        self.assertEqual(withdrawn, history)

    def test_the_bundled_pack_is_schema_validated_once_per_hash(self):
        from unittest.mock import patch
        knowledge.load_pack()
        with patch.object(knowledge, "validate_pack", wraps=knowledge.validate_pack) as validate:
            first, second = knowledge.load_pack(), knowledge.load_pack()

        self.assertEqual(validate.call_count, 0)
        self.assertIsNot(first, second)

    def test_the_search_passage_leaves_out_limitations_to_fit_the_encoder(self):
        pattern = knowledge.load_pack()["patterns"][0]

        text = knowledge.passage(pattern)

        self.assertIn(pattern["prevention"], text)
        self.assertNotIn(pattern["limitations"], text)

    def test_a_candidate_cannot_claim_verified_status(self):
        pack = pack_build.build_pack(knowledge.load_pack(), [(self.card, pack_build.copy_evidence(
            self.card, self.roots, PINS, self.dest, "data/cve-expansion/sources"))], "2026-10-29")
        broken = copy.deepcopy(pack)
        added = next(p for p in broken["patterns"] if p["cve_id"] == "CVE-2099-12345")
        added["verification_status"] = "source_observed"

        with self.assertRaises(ValueError):
            knowledge.validate_pack(broken)


if __name__ == "__main__":
    unittest.main()
