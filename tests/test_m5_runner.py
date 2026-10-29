"""M5 host commands and trace claims are bounded to actual events."""

import unittest

from scripts.run_m5 import command_for_arm, inspect_trace


class M5RunnerTests(unittest.TestCase):
    def test_only_c_receives_paladin_mcp(self):
        common = dict(executable="codex.exe", task="C:/task", output="C:/out",
                      model="gpt-6-sol", effort="medium", project="C:/project")
        a = command_for_arm("A", **common)
        b = command_for_arm("B", **common)
        c = command_for_arm("C", **common)
        self.assertNotIn("mcp_servers.paladin.command", " ".join(a))
        self.assertNotIn("mcp_servers.paladin.command", " ".join(b))
        self.assertIn("mcp_servers.paladin.command", " ".join(c))
        self.assertIn("--ignore-user-config", c)
        self.assertIn("--ephemeral", c)

    def test_search_without_completed_evidence_or_usage_is_not_consumed(self):
        events = [
            {"type": "item.completed", "item": {
                "type": "mcp_tool_call", "server": "paladin", "tool": "search_prevention_patterns",
                "status": "completed", "result": {"structured_content": {"status": "complete"}}}},
            {"type": "item.completed", "item": {"type": "file_change", "status": "completed"}},
        ]
        result = inspect_trace(events)
        self.assertTrue(result["called"])
        self.assertFalse(result["consumed"])

    def test_consumption_requires_evidence_then_agent_use_before_edit(self):
        events = [
            {"type": "item.completed", "item": {
                "type": "mcp_tool_call", "server": "paladin", "tool": "get_pattern_evidence",
                "status": "completed", "result": {"structured_content": {
                    "status": "complete", "pattern_id": "CVE-2025-10000"}}}},
            {"type": "item.completed", "item": {
                "type": "agent_message", "text": "CVE-2025-10000 suggests validating the input."}},
            {"type": "item.completed", "item": {"type": "file_change", "status": "completed"}},
        ]
        result = inspect_trace(events)
        self.assertTrue(result["called"])
        self.assertTrue(result["consumed"])
        self.assertEqual(result["pattern_ids"], ["CVE-2025-10000"])


if __name__ == "__main__":
    unittest.main()
