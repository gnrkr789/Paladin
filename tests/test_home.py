"""One Paladin home per user for search state; project checks read the workspace (plan: paladin-shared-home)."""
import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from paladin import advisory, home


class HomeTests(unittest.TestCase):
    def test_the_environment_variable_wins(self):
        with patch.dict(os.environ, {"PALADIN_HOME": "C:/somewhere/paladin-home"}):
            self.assertEqual(home.default_home(), Path("C:/somewhere/paladin-home"))

    def test_the_platform_default_is_a_user_data_folder(self):
        env = {key: value for key, value in os.environ.items() if key != "PALADIN_HOME"}
        # Not %LOCALAPPDATA%: MSIX-packaged hosts (Claude and Codex desktop apps) get a private copy of it.
        with patch.dict(os.environ, dict(env, LOCALAPPDATA="C:/Users/u/AppData/Local"), clear=True), \
                patch.object(home.sys, "platform", "win32"), \
                patch.object(home.Path, "home", return_value=Path("C:/Users/u")):
            self.assertEqual(home.default_home(), Path("C:/Users/u/.paladin"))
        with patch.dict(os.environ, dict(env, XDG_DATA_HOME="/home/u/.data"), clear=True), \
                patch.object(home.sys, "platform", "linux"):
            self.assertEqual(home.default_home(), Path("/home/u/.data/paladin"))


class SplitTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.workspace, self.home = Path(folder.name) / "project", Path(folder.name) / "home"
        self.workspace.mkdir()
        self.home.mkdir()

    def test_search_reads_the_home_and_project_checks_read_the_workspace(self):
        seen = {}

        def search(root, intent, **kwargs):
            seen["search"] = Path(root)
            return {"status": "complete", "matches": []}

        def dependencies(root, paths=None):
            seen["deps"] = Path(root)
            return {"status": "clean", "findings": []}

        with patch("paladin.knowledge.search_patterns", search), \
                patch("paladin.dependency_check.check_workspace", dependencies):
            advisory.dispatch(self.workspace, "search_prevention_patterns", {"intent": "safe uploads"}, home=self.home)
            advisory.dispatch(self.workspace, "check_dependencies", {}, home=self.home)

        self.assertEqual(seen, {"search": self.home, "deps": self.workspace})

    def test_the_cli_uses_home_and_keeps_workspace_as_the_old_spelling(self):
        from paladin.cli import main
        seen = []

        def status(root):
            seen.append(Path(root))
            return {"status": "unavailable"}

        with patch("paladin.knowledge.knowledge_status", status), contextlib.redirect_stdout(io.StringIO()), \
                patch.dict(os.environ, {"PALADIN_HOME": str(self.home)}):
            main(["patterns", "status"])
            main(["patterns", "status", "--home", str(self.workspace)])
            main(["patterns", "status", "--workspace", str(self.workspace)])

        self.assertEqual(seen, [self.home, self.workspace, self.workspace])

    def test_check_results_with_findings_fit_the_tool_output_schema(self):
        from jsonschema import Draft202012Validator
        (self.workspace / "vcs.py").write_text("import subprocess\ndef switch(branch):\n"
                                               "    subprocess.check_output(['hg', 'checkout', branch])\n",
                                               encoding="ascii")
        (self.workspace / "requirements.txt").write_text("pyyaml==3.13\n", encoding="ascii")

        changes = advisory.dispatch(self.workspace, "check_changes", {"paths": ["vcs.py"]}, home=self.home)
        dependencies = advisory.dispatch(self.workspace, "check_dependencies", {}, home=self.home)

        for result in (changes, dependencies):
            self.assertEqual((result["status"], result["outcome"]), ("complete", "findings"))
            Draft202012Validator(advisory.OUTPUT_SCHEMA).validate(result)

    def test_the_mcp_worker_gets_both_folders(self):
        from paladin.mcp_server import WorkerRunner

        runner = WorkerRunner(self.workspace, home=self.home)

        self.assertEqual((runner.root, runner.home), (self.workspace.resolve(), self.home.resolve()))
        self.assertEqual(runner.command("check_changes")[-4:], ["--home", str(self.home.resolve()), "--tool",
                                                                 "check_changes"])


if __name__ == "__main__":
    unittest.main()
