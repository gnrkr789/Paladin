"""Evidence ships with Paladin; verified cases live in the home (plan: paladin-shared-home)."""
import contextlib
import hashlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from paladin import advisory
from paladin.knowledge import _resource, load_pack


def evidence_args(pattern_id, **extra):
    return dict({"pattern_id": pattern_id, "pack_sha256": hashlib.sha256(_resource("prevention-pack.json")).hexdigest()},
                **extra)


class EvidencePackageTests(unittest.TestCase):
    def test_the_packaged_evidence_holds_every_source_family(self):
        root = advisory.evidence_root()

        for folder in ("m0/sources", "m2/sources", "cve-expansion/sources"):
            self.assertTrue((root / folder).is_dir(), folder)
        self.assertTrue((root / "THIRD_PARTY.md").is_file())

    def test_excerpts_work_from_any_project_including_patch_checked_cards(self):
        pattern = next(p for p in load_pack()["patterns"] if p["verification_status"] == "patch_checked")
        with tempfile.TemporaryDirectory() as project:
            result = advisory.dispatch(Path(project), "get_pattern_evidence",
                                       evidence_args(pattern["pattern_id"], include_excerpt=True))

        self.assertEqual({o["reason"] for o in result["omissions"]} - {"excerpt_byte_limit"}, set())
        self.assertTrue(all(item.get("excerpt") for item in result["evidence"]))


class CaseHomeTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.project, self.home = Path(folder.name) / "project", Path(folder.name) / "home"
        self.project.mkdir()
        (self.home / ".paladin").mkdir(parents=True)

    def test_the_cases_cli_records_in_the_home(self):
        from paladin.cli import main
        seen = []

        def references(root, cve):
            seen.append(Path(root))
            return {"status": "complete", "cases": []}

        with patch("paladin.case_pipeline.verified_case_references", references), \
                contextlib.redirect_stdout(io.StringIO()), patch.dict(os.environ, {"PALADIN_HOME": str(self.home)}):
            main(["cases", "list", "--cve", "CVE-2022-24065"])

        self.assertEqual(seen, [self.home])

    def test_guidance_reads_verified_cases_from_the_home(self):
        (self.home / ".paladin" / "cases.sqlite3").write_bytes(b"")
        seen = []

        def references(root, cve):
            seen.append(Path(root))
            return {"status": "complete", "cases": []}

        from paladin.guidance import load_guidance
        claim = load_guidance()["claims"][0]
        pack_sha = hashlib.sha256(_resource("prevention-pack.json")).hexdigest()
        guidance_sha = hashlib.sha256(_resource("guidance-pack.json")).hexdigest()
        with patch("paladin.case_pipeline.verified_case_references", references):
            advisory.dispatch(self.project, "get_prevention_guidance",
                              {"pattern_id": claim["pattern_id"], "pack_sha256": pack_sha,
                               "guidance_sha256": guidance_sha}, home=self.home)

        self.assertEqual(seen, [self.home])


if __name__ == "__main__":
    unittest.main()
