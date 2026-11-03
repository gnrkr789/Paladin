"""Dependency versions against collected advisory ranges (plan: paladin-dependency-check)."""
import json
from pathlib import Path
import tempfile
import unittest

from paladin import dependency_check as deps

OSV = {"affected": [
    {"package": {"ecosystem": "PyPI", "name": "Flask_Login"},
     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.6.3"}]},
                {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc"}]}]},
    {"package": {"ecosystem": "npm", "name": "flask-login"},
     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9"}]}]}]}
LISTED = {"affected": [{"package": {"ecosystem": "PyPI", "name": "roundup"}, "versions": ["1.4.1", "1.4.2"]}]}
INDEX = {"schema_version": 1, "entries": [
    {"cve_id": "CVE-2099-0001", "package": "flask-login", "title": "Open redirect after login",
     "ranges": [{"introduced": "0", "fixed": "0.6.3"}], "versions": []},
    {"cve_id": "CVE-2099-0002", "package": "pyyaml", "title": "Full loader builds objects",
     "ranges": [{"introduced": "5.1", "last_affected": "5.3.1"}], "versions": []},
    {"cve_id": "CVE-2099-0003", "package": "roundup", "title": "Escaping in templates",
     "ranges": [], "versions": ["1.4.1", "1.4.2"]}]}


class AdvisoryIndexTests(unittest.TestCase):
    def test_only_pypi_ecosystem_ranges_are_kept_with_normalized_names(self):
        self.assertEqual(deps.affected_entries(OSV),
                         [{"package": "flask-login", "ranges": [{"introduced": "0", "fixed": "0.6.3"}], "versions": []}])

    def test_an_explicit_version_list_is_kept_when_there_is_no_range(self):
        self.assertEqual(deps.affected_entries(LISTED),
                         [{"package": "roundup", "ranges": [], "versions": ["1.4.1", "1.4.2"]}])

    def test_ranges_follow_osv_semantics(self):
        entry = INDEX["entries"][1]
        for version, expected in (("5.0", False), ("5.1", True), ("5.3.1", True), ("5.4", False)):
            self.assertEqual(deps.is_affected(version, entry), expected, version)
        self.assertTrue(deps.is_affected("0.6.2", INDEX["entries"][0]))
        self.assertFalse(deps.is_affected("0.6.3", INDEX["entries"][0]))
        self.assertTrue(deps.is_affected("1.4.2", INDEX["entries"][2]))


class ParseTests(unittest.TestCase):
    def test_requirements_pins_unpinned_and_noise(self):
        text = ("# app\nFlask_Login==0.6.2 ; python_version > '3.8'  # pinned\n-r base.txt\n"
                "requests>=2\nPyYAML === 5.3.1 \\\n    --hash=sha256:abc\ngit+https://x/y.git\nflask\n")

        pins, unpinned = deps.parse_requirements(text)

        self.assertEqual(pins, [("flask-login", "0.6.2", 2), ("pyyaml", "5.3.1", 5)])
        self.assertEqual(unpinned, [("requests", 4), ("flask", 8)])

    def test_lock_files_give_every_locked_version(self):
        uv = '[[package]]\nname = "Flask-Login"\nversion = "0.6.2"\n\n[[package]]\nname = "rich"\nversion = "13"\n'
        pipfile = json.dumps({"default": {"pyyaml": {"version": "==5.3.1"}}, "develop": {"x": {"git": "u"}}})

        self.assertEqual(deps.parse_lock("uv.lock", uv), [("flask-login", "0.6.2", None), ("rich", "13", None)])
        self.assertEqual(deps.parse_lock("poetry.lock", uv), [("flask-login", "0.6.2", None), ("rich", "13", None)])
        self.assertEqual(deps.parse_lock("Pipfile.lock", pipfile), [("pyyaml", "5.3.1", None)])

    def test_pyproject_pins_count_and_ranges_are_unpinned(self):
        text = '[project]\nname = "app"\ndependencies = ["flask-login==0.6.2", "requests>=2"]\n'

        self.assertEqual(deps.parse_pyproject(text), ([("flask-login", "0.6.2", None)], [("requests", None)]))


class CheckTests(unittest.TestCase):
    def test_affected_pins_are_findings_and_the_rest_is_reported_honestly(self):
        text = "flask-login==0.6.2\npyyaml==5.4\nroundup==1.4.2\nrequests>=2\nweird==not-a-version\n"

        result = deps.check_text("requirements.txt", text, INDEX)

        self.assertEqual([(f["package"], f["cve_id"], f["line"]) for f in result["findings"]],
                         [("flask-login", "CVE-2099-0001", 1), ("roundup", "CVE-2099-0003", 3)])
        self.assertEqual(result["findings"][0]["fixed_in"], ["0.6.3"])
        self.assertEqual(result["findings"][0]["title"], "Open redirect after login")
        self.assertEqual(result["unpinned"], ["requests"])
        self.assertTrue(any("weird" in note for note in result["notes"]))
        self.assertEqual(result["checked"], 4)

    def test_the_workspace_check_finds_dependency_files_and_skips_others(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "requirements-dev.txt").write_text("flask-login==0.6.2\n", encoding="ascii")
            (root / "uv.lock").write_text('[[package]]\nname = "pyyaml"\nversion = "5.2"\n', encoding="ascii")
            (root / "notes.txt").write_text("flask-login==0.6.2\n", encoding="ascii")

            result = deps.check_workspace(root, index=INDEX)

        self.assertEqual(result["status"], "findings")
        self.assertEqual(sorted((f["file"], f["cve_id"]) for f in result["findings"]),
                         [("requirements-dev.txt", "CVE-2099-0001"), ("uv.lock", "CVE-2099-0002")])

    def test_the_packaged_index_covers_pack_cves_and_flags_a_known_case(self):
        index = deps.load_index()

        self.assertGreater(len({entry["cve_id"] for entry in index["entries"]}), 400)
        result = deps.check_text("requirements.txt", "pyyaml==3.13\n", index)
        self.assertIn("CVE-2017-18342", {finding["cve_id"] for finding in result["findings"]})


class BoundaryTests(unittest.TestCase):
    def test_given_paths_outside_the_workspace_or_not_files_are_skipped_with_a_note(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "ws"
            root.mkdir()
            (root / "requirements.txt").write_text("flask-login==0.6.2\n", encoding="ascii")
            (Path(folder) / "requirements.txt").write_text("flask-login==0.6.2\n", encoding="ascii")

            result = deps.check_workspace(root, ["../requirements.txt", str(Path(folder) / "requirements.txt"), ".",
                                                 "requirements.txt"], index=INDEX)

        self.assertEqual(result["files"], ["requirements.txt"])
        self.assertEqual(len(result["notes"]), 3)

    def test_same_line_hashes_and_optional_dependencies_are_pins(self):
        self.assertEqual(deps.parse_requirements("pyyaml==5.3.1 --hash=sha256:abc\n")[0], [("pyyaml", "5.3.1", 1)])
        text = ('[project]\ndependencies = []\n[project.optional-dependencies]\ndev = ["flask-login==0.6.2"]\n'
                '[dependency-groups]\ntest = ["pyyaml==5.3.1", {include-group = "dev"}]\n')
        self.assertEqual(deps.parse_pyproject(text)[0], [("flask-login", "0.6.2", None), ("pyyaml", "5.3.1", None)])


class HookAndToolTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()

    def test_writing_an_affected_pin_gives_a_review_note_with_the_fixed_version(self):
        from paladin.agent_hook import claude_code_hook
        path = self.root / "requirements.txt"
        path.write_text("pyyaml==3.13\nflask>=2\n", encoding="ascii")

        output = claude_code_hook({"tool_name": "Write", "tool_input": {"file_path": str(path)}}, self.root)

        self.assertNotIn("decision", output)
        context = output["hookSpecificOutput"]["additionalContext"]
        for text in ("requirements.txt:1", "pyyaml 3.13", "CVE-2017-18342", "Fixed in"):
            self.assertIn(text, context)

    def test_a_clean_lock_edit_is_silent_and_codex_patches_are_checked_too(self):
        from paladin.agent_hook import claude_code_hook, codex_hook
        lock = self.root / "uv.lock"
        lock.write_text('[[package]]\nname = "pyyaml"\nversion = "6.0.2"\n', encoding="ascii")
        self.assertIsNone(claude_code_hook({"tool_name": "Write", "tool_input": {"file_path": str(lock)}}, self.root))

        (self.root / "requirements.txt").write_text("pyyaml==3.13\n", encoding="ascii")
        patch_text = "*** Begin Patch\n*** Add File: requirements.txt\n+pyyaml==3.13\n*** End Patch\n"
        output = codex_hook({"tool_name": "apply_patch", "tool_input": {"command": patch_text}, "cwd": str(self.root)},
                            self.root)
        self.assertIn("CVE-2017-18342", output["hookSpecificOutput"]["additionalContext"])

    def test_an_unreadable_dependency_file_is_reported_not_silent(self):
        from paladin.agent_hook import claude_code_hook
        path = self.root / "pyproject.toml"
        path.write_text("[project\n", encoding="ascii")

        output = claude_code_hook({"tool_name": "Write", "tool_input": {"file_path": str(path)}}, self.root)

        self.assertIn("incomplete", output["hookSpecificOutput"]["additionalContext"])

    def test_a_codex_block_keeps_its_decision_and_carries_the_dependency_note(self):
        from paladin.agent_hook import codex_hook
        (self.root / "requirements.txt").write_text("pyyaml==3.13\n", encoding="ascii")
        (self.root / "vcs.py").write_text("import subprocess\ndef switch(branch):\n"
                                          "    subprocess.check_output(['hg', 'checkout', branch])\n", encoding="ascii")
        patch_text = ("*** Begin Patch\n*** Add File: vcs.py\n+x\n*** Add File: requirements.txt\n+pyyaml==3.13\n"
                      "*** End Patch\n")

        output = codex_hook({"tool_name": "apply_patch", "tool_input": {"command": patch_text}, "cwd": str(self.root)},
                            self.root)

        self.assertEqual(output["decision"], "block")
        self.assertIn("CVE-2022-24065", output["reason"])
        self.assertIn("CVE-2017-18342", output["reason"])

    def test_the_text_cli_prints_each_finding(self):
        import contextlib, io
        from paladin.cli import main
        (self.root / "requirements.txt").write_text("pyyaml==3.13\nflask\n", encoding="ascii")
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            main(["deps", "check", "--workspace", str(self.root)])

        for text in ("requirements.txt:1", "pyyaml 3.13", "CVE-2017-18342", "fixed in", "not pinned: flask"):
            self.assertIn(text, output.getvalue())

    def test_the_mcp_tool_and_cli_report_the_workspace_findings(self):
        import contextlib, io
        from paladin import advisory
        from paladin.cli import main
        (self.root / "requirements.txt").write_text("pyyaml==3.13\n", encoding="ascii")

        result = advisory.dispatch(self.root, "check_dependencies", {})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["deps", "check", "--workspace", str(self.root), "--json"])

        self.assertEqual((result["status"], result["outcome"]), ("complete", "findings"))
        self.assertIn("CVE-2017-18342", {f["cve_id"] for f in result["findings"]})
        self.assertEqual(code, 1, "findings exit 1 for CI, like pip-audit")
        self.assertEqual(json.loads(output.getvalue())["findings"], result["findings"])


if __name__ == "__main__":
    unittest.main()
