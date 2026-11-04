"""Whole-project check for the /paladin and $paladin skill: every project Python file, one call."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from paladin import advisory, change_check

EXPOSED = "import subprocess\ndef switch(branch):\n    subprocess.check_output(['hg', 'checkout', branch])\n"
SAFE = "def add(a, b):\n    return a + b\n"


class ProjectCheckTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="ascii")

    def test_a_nested_project_file_with_a_cve_pattern_is_reported_and_clean_files_are_only_counted(self):
        self.write("app/vcs/switch.py", EXPOSED)
        self.write("app/math.py", SAFE)

        result = change_check.check_project(self.root)

        self.assertEqual(result["status"], "findings")
        self.assertEqual(result["checked_files"], 2)
        self.assertEqual([item["path"] for item in result["files"]], ["app/vcs/switch.py"])
        self.assertEqual(result["files"][0]["findings"][0]["severity"], "block")

    def test_rule_text_appears_once_and_files_with_blocking_findings_come_first(self):
        review = "import pickle\ndef load(blob):\n    return pickle.loads(blob)\n"
        self.write("a_review.py", review)
        self.write("b_review.py", review)
        self.write("z_block.py", EXPOSED)

        result = change_check.check_project(self.root)

        self.assertEqual([item["path"] for item in result["files"]], ["z_block.py", "a_review.py", "b_review.py"])
        self.assertEqual(result["totals"], {"block": 1, "review": 2})
        held = result["rules"]["pickle-load-non-constant-data-v1"]
        self.assertTrue(held["fix"] and held["title"])
        self.assertNotIn("fix", result["files"][1]["findings"][0])

    def test_a_large_result_is_trimmed_to_the_response_budget_keeping_blocking_files(self):
        self.write("z_block.py", EXPOSED)
        filler = "import pickle\n" + "".join("def f{0}(b):\n    return pickle.loads(b)\n".format(i) for i in range(5))
        for index in range(200):
            self.write("pkg/m{:03d}.py".format(index), filler)

        result = advisory.dispatch(self.root, "check_project", {})

        self.assertEqual(result["status"], "partial")
        self.assertGreater(result["omitted_count"], 0)
        self.assertEqual(result["files"][0]["path"], "z_block.py")

    def test_the_hardcoded_mercurial_rules_carry_their_fix_and_cve_under_rules(self):
        self.write("switch.py", EXPOSED)

        rule = change_check.check_project(self.root)["rules"]["CVE-2022-24065:mercurial-checkout-v1"]

        self.assertEqual(rule["fix"], change_check.GUIDANCE["CVE-2022-24065:mercurial-checkout-v1"]["fix"])
        self.assertEqual(rule["cve_ids"], ["CVE-2022-24065"])

    def test_notes_per_file_are_capped_so_one_noisy_file_cannot_fill_the_response(self):
        self.write("noisy.py", "import subprocess\n" + "subprocess.run(a)\n" * 400)

        notes = change_check.check_paths(self.root, ["noisy.py"])["files"][0]["notes"]

        self.assertEqual(len(notes), change_check.MAX_NOTES_PER_FILE + 1)
        self.assertIn("more notes not shown", notes[-1])

    def test_trimming_check_changes_drops_files_without_blocks_before_a_blocking_file(self):
        paths = []
        for index in range(19):
            self.write("n{:02d}.py".format(index), "import pickle\n" + "".join(
                "def f{0}(b):\n    return pickle.loads(b)\n".format(i) for i in range(3)))
            paths.append("n{:02d}.py".format(index))
        self.write("z_block.py", EXPOSED)
        with mock.patch.object(advisory, "MAX_RESULT_BYTES", 12000):
            result = advisory.dispatch(self.root, "check_changes", {"paths": paths + ["z_block.py"]})

        self.assertEqual(result["status"], "partial")
        self.assertIn("z_block.py", [item["path"] for item in result["files"]])

    @unittest.skipUnless(os.name == "nt", "junctions are Windows folders")
    def test_a_junction_to_a_folder_outside_the_project_is_not_walked(self):
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        Path(outside.name, "far.py").write_text(EXPOSED, encoding="ascii")
        self.write("app/main.py", SAFE)
        made = subprocess.run(["cmd", "/c", "mklink", "/J", str(self.root / "shared"), outside.name],
                              capture_output=True)
        if made.returncode:
            self.skipTest("mklink /J unavailable")

        result = change_check.check_project(self.root)

        self.assertEqual((result["checked_files"], result["files"]), (1, []))
        self.assertIn("link directory skipped: shared", result["notes"])
        self.assertEqual(result["status"], "partial")

    def test_an_unreadable_folder_is_reported_not_silently_skipped(self):
        self.write("app/main.py", SAFE)

        def failing_walk(root, onerror=None, **kwargs):
            onerror(PermissionError(13, "denied", str(Path(root) / "locked")))
            yield str(root), [], []

        with mock.patch.object(change_check.os, "walk", failing_walk):
            result = change_check.check_project(self.root)

        self.assertEqual(result["status"], "partial")
        self.assertIn("directory inaccessible", " ".join(result["notes"]))

    def test_the_directory_limit_makes_the_result_partial(self):
        for index in range(3):
            self.write("d{}/m.py".format(index), SAFE)

        with mock.patch.object(change_check, "MAX_PROJECT_DIRS", 2):
            result = change_check.check_project(self.root)

        self.assertEqual(result["status"], "partial")
        self.assertIn("directory limit", " ".join(result["notes"]))

    def test_virtual_environments_dependencies_and_hidden_folders_are_not_project_code(self):
        self.write("app/main.py", SAFE)
        for skipped in (".venv/lib/x.py", "env/pyvenv.cfg", "env/lib/x.py", "node_modules/pkg/x.py",
                        "lib/site-packages/pkg/x.py", ".git/hooks/x.py", "app/__pycache__/x.py"):
            self.write(skipped, EXPOSED if skipped.endswith(".py") else "home = C:/Python\n")

        result = change_check.check_project(self.root)

        self.assertEqual((result["status"], result["checked_files"], result["files"]), ("clean", 1, []))

    def test_an_empty_project_is_clean_with_no_files_checked(self):
        result = change_check.check_project(self.root)

        self.assertEqual((result["status"], result["checked_files"]), ("clean", 0))

    def test_the_file_limit_makes_the_result_partial_instead_of_silently_skipping(self):
        for index in range(3):
            self.write("app/m{}.py".format(index), SAFE)

        with mock.patch.object(change_check, "MAX_PROJECT_FILES", 2):
            result = change_check.check_project(self.root)

        self.assertEqual((result["status"], result["checked_files"]), ("partial", 2))
        self.assertIn("file limit", " ".join(result["notes"]))

    def test_the_mcp_tool_checks_the_whole_workspace(self):
        self.write("app/switch.py", EXPOSED)

        result = advisory.dispatch(self.root, "check_project", {})

        self.assertEqual((result["status"], result["outcome"]), ("complete", "findings"))
        self.assertTrue(result["inspection_performed"])
        self.assertEqual(result["files"][0]["path"], "app/switch.py")

    def test_the_mcp_tool_takes_no_arguments(self):
        self.assertEqual(advisory.dispatch(self.root, "check_project", {"paths": ["a.py"]})["status"],
                         "invalid_request")


if __name__ == "__main__":
    unittest.main()
