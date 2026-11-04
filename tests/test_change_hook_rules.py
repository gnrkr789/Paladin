"""Data rules in the change hook: compact review output, edited-lines only, zero-model path (S11-S14)."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from paladin import change_check, data_rules
from paladin.agent_hook import claude_code_hook, codex_hook
from tests.test_data_rules import YAML_LOAD

RUNTIME_RULE = {key: value for key, value in YAML_LOAD.items() if key != "examples"}
UNSAFE = "import yaml\n\ndef read(data):\n    return yaml.load(data)\n"
ROOT = Path(__file__).resolve().parents[1]


class DataRuleHookTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()
        rules = patch.object(change_check, "_DATA_RULES", data_rules.compile_rules([RUNTIME_RULE]))
        rules.start()
        self.addCleanup(rules.stop)

    def write(self, name, text):
        path = self.root / name
        path.write_text(text, encoding="ascii")
        return path

    def edit(self, path, new_string=None, tool="Edit"):
        tool_input = {"file_path": str(path)}
        if new_string is not None:
            tool_input.update(old_string="x", new_string=new_string)
        return claude_code_hook({"hook_event_name": "PostToolUse", "tool_name": tool, "tool_input": tool_input},
                                self.root)

    def test_a_data_rule_finding_is_a_short_review_note_with_the_card_id(self):
        output = self.edit(self.write("load.py", UNSAFE), tool="Write")

        self.assertNotIn("decision", output)
        context = output["hookSpecificOutput"]["additionalContext"]
        for text in ("load.py:4", "yaml-load-unsafe-loader-v1", YAML_LOAD["title"], YAML_LOAD["fix"], "CVE-2020-1747"):
            self.assertIn(text, context)
        self.assertNotIn("Why:", context)
        self.assertLessEqual(len(context), 1500)

    def test_review_findings_beside_a_block_keep_their_fix_and_card(self):
        exposed = "import subprocess\ndef switch(branch):\n    subprocess.check_output(['hg', 'checkout', branch])\n"

        output = self.edit(self.write("both.py", exposed + UNSAFE), tool="Write")

        self.assertEqual(output["decision"], "block")
        review = output["reason"].split("Also review:")[1]
        for text in ("yaml-load-unsafe-loader-v1", YAML_LOAD["fix"], "CVE-2020-1747"):
            self.assertIn(text, review)
        self.assertNotIn("Fix: \n", output["reason"])

    def test_review_findings_on_lines_this_edit_did_not_write_are_not_repeated(self):
        path = self.write("load.py", UNSAFE)

        self.assertIsNone(self.edit(path, new_string="def read(data):"))
        self.assertIsNotNone(self.edit(path, new_string="    return yaml.load(data)"))

    def test_clean_edits_produce_no_output(self):
        self.assertIsNone(self.edit(self.write("safe.py", "import yaml\nyaml.safe_load(s)\n"), tool="Write"))

    def test_codex_patches_report_only_added_lines(self):
        self.write("load.py", UNSAFE)
        untouched = "*** Begin Patch\n*** Update File: load.py\n@@\n-def read(data):\n+def read(data):\n*** End Patch"
        touched = ("*** Begin Patch\n*** Update File: load.py\n@@\n-    return x\n+    return yaml.load(data)\n"
                   "*** End Patch")

        def run(patch_text):
            return codex_hook({"tool_name": "apply_patch", "tool_input": {"command": patch_text},
                               "cwd": str(self.root)}, self.root)

        self.assertIsNone(run(untouched))
        self.assertIn("yaml-load-unsafe-loader-v1", run(touched)["hookSpecificOutput"]["additionalContext"])

    def test_many_review_findings_never_push_a_blocking_finding_out(self):
        source = ("import yaml, subprocess\n" + "".join("yaml.load(s{})\n".format(i) for i in range(60))
                  + "def switch(branch):\n    subprocess.check_output(['hg', 'checkout', branch])\n")

        output = self.edit(self.write("mixed.py", source), tool="Write")

        self.assertEqual(output["decision"], "block")
        self.assertIn("CVE-2022-24065", output["reason"])

    def test_output_stays_within_the_limit_for_many_findings(self):
        source = "import yaml\n" + "".join("yaml.load(s{})\n".format(i) for i in range(200))
        context = self.edit(self.write("many.py", source), tool="Write")["hookSpecificOutput"]["additionalContext"]

        self.assertLessEqual(len(context), 1500)
        self.assertIn("more", context)


class BundledRulesTests(unittest.TestCase):
    def test_bundled_rule_data_loads_and_only_low_unknown_or_held_rules_stay_review(self):
        # Severity plus precision (user, 2026-11-04); tests/test_severity.py checks each rule's level.
        rules = change_check.load_data_rules()

        self.assertTrue(all((rule["severity"] == "review")
                            == (rule["cve_severity"] in {None, "LOW"} or rule["precision_hold"]) for rule in rules))


GUARD = r"""
import builtins, io, json, socket, sys
FORBIDDEN = ("onnxruntime", "pymilvus", "tokenizers", "numpy", "mcp", "anthropic", "urllib.request",
             "http.client", "paladin.embedding", "paladin.knowledge", "paladin.local")
real_import = builtins.__import__
def guarded(name, *args, **kwargs):
    if any(name == item or name.startswith(item + ".") for item in FORBIDDEN):
        raise ImportError("forbidden on the hook path: " + name)
    return real_import(name, *args, **kwargs)
builtins.__import__ = guarded
class NoSocket(socket.socket):
    def __init__(self, *args, **kwargs):
        raise OSError("network is forbidden on the hook path")
socket.socket = NoSocket
from paladin import agent_hook
workspace, target = sys.argv[1], sys.argv[2]
payload = json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Write", "tool_input": {"file_path": target}})
out = io.StringIO()
agent_hook.main(workspace, io.StringIO(payload), out)
loaded = sorted(name for name in sys.modules if any(name == item or name.startswith(item + ".") for item in FORBIDDEN))
print(json.dumps({"output": out.getvalue(), "loaded": loaded}))
"""


class ZeroModelPathTests(unittest.TestCase):
    def test_the_hook_runs_without_model_embedding_or_network_modules(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "vcs.py"
            target.write_text("import subprocess\ndef f(b):\n    subprocess.run(['hg', 'checkout', b])\n",
                              encoding="ascii")
            env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
            done = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, %r)\n" % str(ROOT / "src")
                                   + GUARD, folder, str(target)], capture_output=True, text=True, env=env, timeout=60)

        self.assertEqual(done.returncode, 0, done.stderr)
        result = json.loads(done.stdout.strip().splitlines()[-1])
        self.assertEqual(result["loaded"], [])
        self.assertIn("CVE-2022-24065", result["output"])
        self.assertNotIn("unavailable", result["output"])


if __name__ == "__main__":
    unittest.main()
