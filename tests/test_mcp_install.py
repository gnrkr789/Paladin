"""paladin mcp install: project-scoped MCP registration for Claude Code and Codex."""
import json
import os
from pathlib import Path
import tempfile
import tomllib
import unittest

from paladin import mcp_install

COMMAND = ["C:/Python/python.exe", "-I", "-m", "paladin.cli"]


class McpInstallTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()

    def test_claude_code_gets_a_project_mcp_entry_and_other_servers_stay(self):
        (self.root / ".mcp.json").write_text(json.dumps({"mcpServers": {"other": {"command": "x"}}}), encoding="utf-8")

        mcp_install.install(self.root, COMMAND, "claude-code")
        mcp_install.install(self.root, COMMAND, "claude-code")

        servers = json.loads((self.root / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]
        self.assertEqual(set(servers), {"other", "paladin"})
        self.assertEqual(servers["paladin"], {"command": "C:/Python/python.exe",
                                              "args": ["-I", "-m", "paladin.cli", "mcp", "--workspace",
                                                       self.root.as_posix()]})

    def test_codex_gets_one_managed_block_in_the_project_config(self):
        config = self.root / ".codex" / "config.toml"
        config.parent.mkdir()
        config.write_text('model = "x"\n', encoding="utf-8")

        mcp_install.install(self.root, COMMAND, "codex")
        result = mcp_install.install(self.root, COMMAND, "codex")

        data = tomllib.loads(config.read_text(encoding="utf-8"))
        self.assertEqual(data["model"], "x")
        self.assertEqual(data["mcp_servers"]["paladin"]["args"][-1], self.root.as_posix())
        self.assertEqual(config.read_text(encoding="utf-8").count("[mcp_servers.paladin]"), 1)
        self.assertIn("trust", result["next_step"])

    def test_a_hand_written_paladin_entry_or_invalid_settings_are_refused(self):
        config = self.root / ".codex" / "config.toml"
        config.parent.mkdir()
        config.write_text('[mcp_servers.paladin]\ncommand = "mine"\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "existing_unmanaged_entry"):
            mcp_install.install(self.root, COMMAND, "codex")

        (self.root / ".mcp.json").write_text("[]", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "invalid_settings"):
            mcp_install.install(self.root, COMMAND, "claude-code")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks")
    def test_a_linked_config_file_is_refused(self):
        target = self.root / "elsewhere.json"
        target.write_text("{}", encoding="utf-8")
        try:
            (self.root / ".mcp.json").symlink_to(target)
        except OSError:
            self.skipTest("symlinks need privileges here")
        with self.assertRaisesRegex(ValueError, "unsafe_settings_file"):
            mcp_install.install(self.root, COMMAND, "claude-code")

    def test_a_missing_workspace_is_refused_for_both_hosts(self):
        for host in ("claude-code", "codex"):
            with self.assertRaisesRegex(ValueError, "invalid_workspace"):
                mcp_install.install(self.root / "typo", COMMAND, host)
        self.assertFalse((self.root / "typo").exists())

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks")
    def test_a_linked_codex_folder_is_refused(self):
        outside = self.root / "outside"
        outside.mkdir()
        try:
            (self.root / ".codex").symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("symlinks need privileges here")
        with self.assertRaisesRegex(ValueError, "unsafe_settings_directory"):
            mcp_install.install(self.root, COMMAND, "codex")

    def test_a_path_outside_the_basic_plane_still_gives_valid_toml(self):
        project = self.root / ("proj-" + chr(0x1F600))
        project.mkdir()

        mcp_install.install(project, COMMAND, "codex")

        data = tomllib.loads((project / ".codex" / "config.toml").read_text(encoding="utf-8"))
        self.assertEqual(data["mcp_servers"]["paladin"]["args"][-1], project.resolve().as_posix())

    def test_each_host_gets_the_paladin_skill_where_it_reads_project_skills(self):
        for host, folder in (("claude-code", ".claude/skills/paladin"), ("codex", ".agents/skills/paladin")):
            mcp_install.install(self.root, COMMAND, host)
            result = mcp_install.install(self.root, COMMAND, host)

            skill = (self.root / folder / "SKILL.md").read_text(encoding="utf-8")
            self.assertTrue(skill.startswith("---\nname: paladin\ndescription: "), host)
            for tool in ("check_project", "check_dependencies", "search_prevention_patterns"):
                self.assertIn(tool, skill)
            self.assertEqual(Path(result["skill"]), self.root / folder / "SKILL.md")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks")
    def test_a_linked_skills_folder_is_refused(self):
        outside = self.root / "outside"
        outside.mkdir()
        (self.root / ".claude").mkdir()
        try:
            (self.root / ".claude" / "skills").symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("symlinks need privileges here")
        with self.assertRaisesRegex(ValueError, "unsafe_settings_directory"):
            mcp_install.install(self.root, COMMAND, "claude-code")
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse((self.root / ".mcp.json").exists())

    def test_the_cli_installs_and_reports_errors_as_json(self):
        import contextlib, io
        from paladin.cli import main
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["mcp", "install", "--host", "codex", "--workspace", str(self.root)])
        self.assertEqual((code, json.loads(output.getvalue())["status"]), (0, "installed"))

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["mcp", "install", "--workspace", str(self.root / "typo")])
        self.assertEqual((code, json.loads(output.getvalue())), (1, {"status": "unavailable", "error": "invalid_workspace"}))


if __name__ == "__main__":
    unittest.main()
