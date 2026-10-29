import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from paladin.candidate_scan import scan_project


class CandidateScanTests(unittest.TestCase):
    def test_dynamic_subcommand_makes_coverage_partial(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "dynamic.py").write_text(
                "import subprocess\nsubprocess.check_output(['hg', command, value])\n", encoding="ascii")
            result = scan_project(root)
            self.assertEqual(result["status"], "partial")
            self.assertTrue(any("dynamic subprocess subcommand" in item for item in result["unsupported_patterns"]))

    def test_single_expanded_argv_is_not_complete_coverage(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "dynamic.py").write_text("import subprocess\nsubprocess.run([*argv])\n", encoding="ascii")
            result = scan_project(root)
            self.assertEqual(result["status"], "partial")
            self.assertTrue(result["unsupported_patterns"])
    def test_dynamic_checkout_and_stable_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = b"import subprocess\ndef clone(repo_type, checkout):\n    subprocess.check_output([repo_type, 'checkout', checkout])\n"
            Path(tmp, "vcs.py").write_bytes(source)
            result = scan_project(tmp)
            self.assertEqual(result["status"], "complete")
            candidate = result["candidates"][0]
            self.assertEqual((candidate["path"], candidate["line"]), ("vcs.py", 3))
            self.assertEqual(candidate["source_sha256"], hashlib.sha256(source).hexdigest())
            self.assertEqual(candidate, scan_project(tmp)["candidates"][0])

    def test_safe_and_unknown_argv(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "safe.py").write_text(
                "import subprocess\ndef f(value):\n"
                "    subprocess.run(['hg', 'checkout', '--', value])\n"
                "    subprocess.run(['hg', 'checkout', 'stable'])\n"
                "    subprocess.run(['git', 'checkout', value])\n", encoding="ascii")
            self.assertEqual(scan_project(tmp)["candidates"], [])
            Path(tmp, "unknown.py").write_text(
                "import subprocess\nsubprocess.run(['hg', 'checkout', *args])\n", encoding="ascii")
            result = scan_project(tmp)
            self.assertEqual(result["status"], "partial")
            self.assertTrue(result["unsupported_patterns"])

    def test_syntax_and_size_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "broken.py").write_bytes(b"def !\n")
            Path(tmp, "large.py").write_bytes(b"x" * 30)
            with patch("paladin.candidate_scan.MAX_FILE_BYTES", 20):
                result = scan_project(tmp)
            self.assertEqual(result["status"], "partial")
            self.assertEqual(len(result["unsupported_patterns"]), 2)

    def test_link_source_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            target = Path(outside, "outside.py")
            target.write_text("import subprocess\nsubprocess.run(['hg', 'checkout', x])\n", encoding="ascii")
            try:
                os.symlink(target, Path(tmp, "link.py"))
            except OSError:
                self.skipTest("Symlink creation unavailable")
            result = scan_project(tmp)
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["candidates"], [])

    def test_non_ascii_root_is_rejected(self):
        with self.assertRaises(ValueError):
            scan_project("project-\u00e9")


if __name__ == "__main__":
    unittest.main()
