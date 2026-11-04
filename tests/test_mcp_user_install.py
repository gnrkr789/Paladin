"""paladin mcp install --user: one install per user, used only when the user calls /paladin or $paladin."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest import mock

from paladin import advisory, mcp_install

COMMAND = ["C:/Python/python.exe", "-I", "-m", "paladin.cli"]


class Runner:
    """Stands in for the claude CLI; records each call. `existing` is what `mcp get` prints."""

    def __init__(self, missing=False, hang=False, existing=None, add_error=None):
        self.calls, self.missing, self.hang, self.existing, self.add_error = [], missing, hang, existing, add_error

    def __call__(self, argv, **kwargs):
        if self.missing:
            raise FileNotFoundError("claude")
        if self.hang:
            raise subprocess.TimeoutExpired(argv, 60)
        self.calls.append(argv)
        if argv[2] == "get":
            return mock.Mock(returncode=1 if self.existing is None else 0, stdout=self.existing or "", stderr="")
        if argv[2] == "add-json" and self.add_error:
            return mock.Mock(returncode=1, stdout="", stderr=self.add_error)
        return mock.Mock(returncode=0, stdout="", stderr="")


class UserInstallTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.home = Path(folder.name).resolve()
        patches = [mock.patch.object(Path, "home", return_value=self.home),
                   mock.patch.dict(os.environ, {"CODEX_HOME": "", "CLAUDE_CONFIG_DIR": ""})]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def test_codex_gets_a_user_server_without_a_fixed_workspace_and_an_explicit_only_skill(self):
        mcp_install.install_user(COMMAND, "codex")
        result = mcp_install.install_user(COMMAND, "codex")

        config = (self.home / ".codex" / "config.toml").read_text(encoding="utf-8")
        server = tomllib.loads(config)["mcp_servers"]["paladin"]
        self.assertEqual(server["args"], ["-I", "-m", "paladin.cli", "mcp"])
        self.assertEqual(config.count("[mcp_servers.paladin]"), 1)
        skill = self.home / ".agents" / "skills" / "paladin"
        self.assertTrue((skill / "SKILL.md").is_file())
        self.assertIn("allow_implicit_invocation: false", (skill / "agents" / "openai.yaml").read_text(encoding="utf-8"))
        self.assertEqual(result["usage"], "$paladin")

    def test_codex_home_is_respected(self):
        codex_home = self.home / "custom-codex"
        with mock.patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}):
            mcp_install.install_user(COMMAND, "codex")

        self.assertTrue((codex_home / "config.toml").is_file())

    def test_claude_code_registers_a_user_server_through_its_cli_and_a_slash_only_skill(self):
        runner = Runner()

        result = mcp_install.install_user(COMMAND, "claude-code", run=runner)

        self.assertEqual([call[2] for call in runner.calls], ["get", "add-json"])
        added = runner.calls[1]
        self.assertEqual(added[1:6], ["mcp", "add-json", "--scope", "user", "paladin"])
        self.assertEqual(json.loads(added[6]), {"type": "stdio", "command": "C:/Python/python.exe",
                                                "args": ["-I", "-m", "paladin.cli", "mcp"]})
        skill = (self.home / ".claude" / "skills" / "paladin" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("\ndisable-model-invocation: true\n", skill.split("---")[1])
        self.assertEqual(result["usage"], "/paladin")

    def test_a_missing_claude_cli_is_reported_and_nothing_is_written(self):
        with self.assertRaisesRegex(ValueError, "claude_cli_not_found"):
            mcp_install.install_user(COMMAND, "claude-code", run=Runner(missing=True))

        self.assertFalse((self.home / ".claude").exists())

    def _junction(self, link, target):
        target.mkdir(parents=True, exist_ok=True)
        link.parent.mkdir(parents=True, exist_ok=True)
        if os.name != "nt" or subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                                             capture_output=True).returncode:
            self.skipTest("junctions need Windows mklink")

    def test_a_refused_skills_folder_registers_no_server_for_either_host(self):
        self._junction(self.home / ".claude" / "skills", self.home / "elsewhere-claude")
        self._junction(self.home / ".agents" / "skills", self.home / "elsewhere-agents")
        runner = Runner()

        for host in ("claude-code", "codex"):
            with self.assertRaisesRegex(ValueError, "unsafe_settings_directory"):
                mcp_install.install_user(COMMAND, host, run=runner)

        self.assertEqual([call[2] for call in runner.calls], ["get"])  # Read-only preflight only.
        self.assertFalse((self.home / ".codex" / "config.toml").exists())

    def test_a_hanging_claude_cli_becomes_an_error_not_a_traceback(self):
        with self.assertRaisesRegex(ValueError, "claude_cli_timeout"):
            mcp_install.install_user(COMMAND, "claude-code", run=Runner(hang=True))

    def test_a_user_server_named_paladin_that_is_not_paladin_is_refused(self):
        runner = Runner(existing="paladin:\n  Command: node\n  Args: other-server.js\n")

        with self.assertRaisesRegex(ValueError, "existing_unmanaged_entry"):
            mcp_install.install_user(COMMAND, "claude-code", run=runner)

        self.assertEqual([call[2] for call in runner.calls], ["get"])

    def test_a_failed_add_reports_the_cli_reason(self):
        with self.assertRaisesRegex(ValueError, "claude_mcp_add_failed: unknown command add-json"):
            mcp_install.install_user(COMMAND, "claude-code", run=Runner(add_error="unknown command add-json\n"))

    def test_uninstall_without_the_claude_cli_still_removes_the_skill(self):
        mcp_install.install_user(COMMAND, "claude-code", run=Runner())

        result = mcp_install.uninstall_user("claude-code", run=Runner(missing=True))

        self.assertFalse((self.home / ".claude" / "skills" / "paladin").exists())
        self.assertEqual(result["server"], "claude_cli_not_found")

    def test_uninstall_removes_the_server_and_the_skill_and_keeps_other_settings(self):
        config = self.home / ".codex" / "config.toml"
        config.parent.mkdir()
        config.write_text('model = "x"\n', encoding="utf-8")
        mcp_install.install_user(COMMAND, "codex")
        runner = Runner()
        mcp_install.install_user(COMMAND, "claude-code", run=runner)

        mcp_install.uninstall_user("codex")
        mcp_install.uninstall_user("claude-code", run=runner)

        self.assertEqual(tomllib.loads(config.read_text(encoding="utf-8")), {"model": "x"})
        self.assertFalse((self.home / ".agents" / "skills" / "paladin").exists())
        self.assertFalse((self.home / ".claude" / "skills" / "paladin").exists())
        self.assertEqual(runner.calls[-1][1:], ["mcp", "remove", "--scope", "user", "paladin"])

    def test_the_cli_installs_for_the_user(self):
        import contextlib, io
        from paladin.cli import main
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["mcp", "install", "--user", "--host", "codex"])
        self.assertEqual((code, json.loads(output.getvalue())["scope"]), (0, "user"))

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["mcp", "install", "--user", "--host", "codex", "--workspace", str(self.home)])
        self.assertEqual((code, json.loads(output.getvalue())["error"]), (1, "user_scope_has_no_workspace"))


class NotAProjectTests(unittest.TestCase):
    def test_a_project_scan_of_the_home_folder_or_a_drive_root_is_refused(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(Path, "home", return_value=Path(folder)):
            for tool in ("check_project", "scan_cve_candidates"):
                result = advisory.dispatch(Path(folder), tool, {})
                self.assertEqual((result["status"], result["reason"]), ("unsupported", "not_a_project_folder"))
            real = Path(folder) / "real"
            real.mkdir()
            if os.name == "nt" and not subprocess.run(["cmd", "/c", "mklink", "/J", str(Path(folder) / "link"),
                                                       str(real)], capture_output=True).returncode:
                with mock.patch.object(Path, "home", return_value=Path(folder) / "link"):
                    self.assertEqual(advisory.dispatch(real, "check_project", {})["reason"], "not_a_project_folder")
            anchor = Path(Path.cwd().anchor)
            self.assertEqual(advisory.dispatch(anchor, "check_project", {})["reason"], "not_a_project_folder")


if __name__ == "__main__":
    unittest.main()
