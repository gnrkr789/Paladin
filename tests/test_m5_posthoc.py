"""Post hoc sensitivity check for bounded evidence excerpts."""

import unittest

from eval.m5_posthoc import evidence_use


def _partial(omissions):
    return {"type": "item.completed", "item": {
        "type": "mcp_tool_call", "server": "paladin",
        "tool": "get_pattern_evidence", "status": "completed",
        "result": {"structured_content": {
            "status": "partial", "pattern_id": "CVE-2021-31542",
            "pack_sha256": "a" * 64,
            "evidence": [{"evidence_id": "patch:" + "b" * 64}],
            "omissions": omissions,
        }},
    }}


class PostHocTests(unittest.TestCase):
    def test_excerpt_limit_with_visible_pre_edit_use(self):
        events = [
            _partial([{"evidence_id": "patch:" + "b" * 64, "reason": "excerpt_byte_limit"}]),
            {"type": "item.completed", "item": {
                "type": "agent_message", "text": "CVE-2021-31542 concerns upload names."}},
            {"type": "item.completed", "item": {
                "type": "file_change", "status": "completed"}},
        ]
        self.assertTrue(evidence_use(events)["consumed"])

    def test_missing_evidence_is_not_counted(self):
        events = [
            _partial([{"evidence_id": "patch:" + "b" * 64, "reason": "hash_mismatch"}]),
            {"type": "item.completed", "item": {
                "type": "agent_message", "text": "CVE-2021-31542 concerns upload names."}},
            {"type": "item.completed", "item": {
                "type": "file_change", "status": "completed"}},
        ]
        self.assertFalse(evidence_use(events)["consumed"])


if __name__ == "__main__":
    unittest.main()
