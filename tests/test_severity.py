"""CVE severity decides whether a data rule blocks (plan: paladin-severity-blocking)."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from paladin import change_check, data_rules, severity
from paladin.agent_hook import claude_code_hook
from tests.test_data_rules import YAML_LOAD

RUNTIME = {key: value for key, value in YAML_LOAD.items() if key != "examples"}
UNSAFE = "import yaml\n\ndef read(data):\n    return yaml.load(data)\n"


class LevelTests(unittest.TestCase):
    def test_ghsa_moderate_reads_as_medium_and_cvss_is_the_fallback(self):
        self.assertEqual(severity.from_ghsa({"database_specific": {"severity": "MODERATE"}}), "MEDIUM")
        self.assertIsNone(severity.from_ghsa({"database_specific": {}}))
        record = {"containers": {"cna": {"metrics": [{"cvssV3_1": {"baseSeverity": "HIGH"}}]},
                                 "adp": [{"metrics": [{"cvssV4_0": {"baseSeverity": "CRITICAL"}}]}]}}
        self.assertEqual(severity.from_cve_record(record), "CRITICAL")
        self.assertIsNone(severity.from_cve_record({"containers": {"cna": {}}}))

    def test_a_rule_takes_its_highest_cve_and_medium_and_above_block(self):
        levels = {"CVE-2020-0001": "LOW", "CVE-2020-0002": "MEDIUM"}
        self.assertEqual(severity.rule_level(["CVE-2020-0001", "CVE-2020-0002"], levels), "MEDIUM")
        self.assertEqual(severity.rule_level(["CVE-2020-0009"], levels), None)
        self.assertEqual([severity.rule_severity(level) for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", None)],
                         ["block", "block", "block", "review", "review"])

    def test_the_packaged_index_covers_the_pack(self):
        index = severity.load_index()["levels"]

        self.assertGreater(len(index), 500)
        self.assertEqual(index["CVE-2017-18342"]["severity"], "CRITICAL")


class HookTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()

    def use(self, **fields):
        rule = dict(RUNTIME, **fields)
        patcher = patch.object(change_check, "_DATA_RULES", data_rules.compile_rules([rule]))
        patcher.start()
        self.addCleanup(patcher.stop)

    def edit(self, text, new_string=None, block_low=False):
        path = self.root / "load.py"
        path.write_text(text, encoding="ascii")
        tool_input = {"file_path": str(path)}
        if new_string is not None:
            tool_input.update(old_string="x", new_string=new_string)
        payload = {"hook_event_name": "PostToolUse", "tool_name": "Edit" if new_string else "Write",
                   "tool_input": tool_input}
        return claude_code_hook(payload, self.root, block_low=block_low)

    def test_a_block_rule_on_a_written_line_blocks_with_its_fix_and_severity(self):
        self.use(severity="block", cve_severity="HIGH")

        output = self.edit(UNSAFE)

        self.assertEqual(output["decision"], "block")
        for text in ("load.py:4", "CVE-2020-1747", "HIGH", YAML_LOAD["fix"]):
            self.assertIn(text, output["reason"])
        self.assertNotIn("Fix: \n", output["reason"])

    def test_a_block_rule_on_old_code_is_only_a_review_note(self):
        self.use(severity="block", cve_severity="HIGH")

        output = self.edit(UNSAFE, new_string="def read(data):")

        self.assertNotIn("decision", output)
        context = output["hookSpecificOutput"]["additionalContext"]
        self.assertIn("load.py:4", context)
        self.assertIn(YAML_LOAD["rule_id"], context)

    def test_old_card_blocks_never_push_an_exact_cve_block_out_of_the_budget(self):
        self.use(severity="block", cve_severity="HIGH")
        source = ("import yaml, subprocess\n" + "".join("yaml.load(s{})\n".format(i) for i in range(60))
                  + "def switch(branch):\n    subprocess.check_output(['hg', 'checkout', branch])\n")

        output = self.edit(source, new_string="import yaml, subprocess")

        self.assertEqual(output["decision"], "block")
        self.assertIn("CVE-2022-24065", output["reason"])

    def test_low_rules_block_only_when_opted_in(self):
        self.use(severity="review", cve_severity="LOW")

        self.assertNotIn("decision", self.edit(UNSAFE))
        self.assertEqual(self.edit(UNSAFE, block_low=True)["decision"], "block")

    def test_a_rule_without_severity_never_blocks_even_when_low_is_opted_in(self):
        self.use(severity="review", cve_severity=None)

        self.assertNotIn("decision", self.edit(UNSAFE, block_low=True))

    def test_shipped_data_cannot_pair_block_with_low_or_unknown(self):
        for level in ("LOW", None):
            with self.assertRaises(ValueError):
                data_rules.load_runtime({"schema_version": 1,
                                         "rules": [dict(RUNTIME, severity="block", cve_severity=level)]})

    def test_install_can_opt_in_to_low_blocking(self):
        from paladin.agent_hook import install_hook
        result = install_hook(self.root, ["python", "-m", "paladin.cli"], "claude-code", block_low=True)
        settings = json.loads(Path(result["settings"]).read_text(encoding="utf-8"))
        command = settings["hooks"]["PostToolUse"][-1]["hooks"][0]["command"]
        self.assertTrue(command.endswith(" --block-low"))


class ShippedRuleTests(unittest.TestCase):
    def test_shipped_rules_follow_the_severity_criterion(self):
        index = severity.load_index()["levels"]
        for rule in change_check.load_data_rules():
            levels = {cve: index[cve]["severity"] for cve in rule["cve_ids"] if cve in index}
            expected = severity.rule_level(rule["cve_ids"], levels)
            self.assertEqual((rule["cve_severity"], rule["severity"]), (expected, severity.rule_severity(expected)),
                             rule["rule_id"])


if __name__ == "__main__":
    unittest.main()
