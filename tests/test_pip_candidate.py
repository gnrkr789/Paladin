import hashlib
from pathlib import Path
import tempfile
import unittest

from paladin.candidate_scan import scan_project


AFFECTED = (
    b"# Preserve this header.\n"
    b"class Mercurial(VersionControl):\n"
    b"    name = 'hg'\n"
    b"    @staticmethod\n"
    b"    def get_base_rev_args(rev: str) -> list:\n"
    b"        return ['-r', rev]  # Preserve this comment.\n"
)
RULE_ID = "CVE-2023-5752:mercurial-revision-v1"


class PipCandidateTests(unittest.TestCase):
    def test_root_scan_finds_pip_pattern_without_path_hint(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "arbitrary" / "backend.py"
            source.parent.mkdir()
            source.write_bytes(AFFECTED)
            candidates = scan_project(root)["candidates"]
            self.assertEqual(len(candidates), 1)
            candidate = candidates[0]
            digest = hashlib.sha256(AFFECTED).hexdigest()
            self.assertEqual(candidate["rule_id"], RULE_ID)
            self.assertEqual(candidate["cve_id"], "CVE-2023-5752")
            self.assertEqual(candidate["path"], "arbitrary/backend.py")
            self.assertEqual(candidate["line"], 6)
            self.assertEqual(candidate["source_sha256"], digest)
            identity = "\0".join((RULE_ID, "arbitrary/backend.py", "6", digest))
            self.assertEqual(candidate["candidate_id"], hashlib.sha256(identity.encode("ascii")).hexdigest())

    def test_repair_changes_only_revision_list_and_clears_candidate(self):
        from paladin.pip_case_adapter import CVE_ID, RULE_ID as adapter_rule, repair_bytes

        expected = AFFECTED.replace(b"['-r', rev]", b"['--rev=' + rev]")
        self.assertEqual(repair_bytes(AFFECTED), expected)
        self.assertEqual((CVE_ID, adapter_rule), ("CVE-2023-5752", RULE_ID))
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "backend.py").write_bytes(expected)
            self.assertEqual(scan_project(folder)["candidates"], [])

    def test_upstream_fixed_pattern_and_unrelated_classes_are_not_candidates(self):
        variants = (
            AFFECTED.replace(b"['-r', rev]", b"[f'-r={rev}']"),
            AFFECTED.replace(b"class Mercurial", b"class Git"),
            AFFECTED.replace(b"get_base_rev_args", b"other_method"),
        )
        with tempfile.TemporaryDirectory() as folder:
            for index, source in enumerate(variants):
                Path(folder, "source%d.py" % index).write_bytes(source)
            self.assertEqual(scan_project(folder)["candidates"], [])

    def test_repair_preserves_crlf_and_multiline_surroundings(self):
        from paladin.pip_case_adapter import repair_bytes

        original = AFFECTED.replace(b"['-r', rev]", b"[\n            '-r',\n            rev,\n        ]").replace(b"\n", b"\r\n")
        repaired = repair_bytes(original)
        self.assertEqual(repaired, AFFECTED.replace(b"['-r', rev]", b"['--rev=' + rev]").replace(b"\n", b"\r\n"))

    def test_repair_rejects_fixed_ambiguous_and_unrecognized_sources(self):
        from paladin.pip_case_adapter import repair_bytes

        invalid = (
            AFFECTED.replace(b"['-r', rev]", b"[f'-r={rev}']"),
            AFFECTED + b"\n" + AFFECTED,
            AFFECTED.replace(b"        return", b"        if rev:\n            return"),
            AFFECTED.replace(b"@staticmethod", b"@other_decorator"),
            AFFECTED.replace(b"['-r', rev]", b"['-r', other]"),
            b"def invalid syntax:\n",
        )
        for source in invalid:
            with self.subTest(source=source), self.assertRaises(ValueError):
                repair_bytes(source)

    def test_cookiecutter_scan_behavior_remains_available(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "backend.py").write_bytes(
                b"import subprocess\nsubprocess.check_output(['hg', 'checkout', revision])\n")
            candidates = scan_project(folder)["candidates"]
            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0]["cve_id"], "CVE-2022-24065")


if __name__ == "__main__":
    unittest.main()
