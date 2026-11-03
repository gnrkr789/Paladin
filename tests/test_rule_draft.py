"""Offline rule drafting from cards: prompt, validation, no-rule answers and merging (S9, S10)."""
import copy
import json
import unittest

from paladin import rule_draft
from tests.test_data_rules import YAML_LOAD

CARD = {"cve_id": "CVE-2020-1747", "family": "unsafe_deserialization", "packages": ["pyyaml"],
        "title": "Full loader can construct arbitrary Python objects",
        "cause": "yaml.load with the full loader builds objects named by the document.",
        "prevention": "Load untrusted YAML with the safe loader only.", "preconditions": ["Untrusted YAML."],
        "limitations": "None.", "fixtures": {"risk": "r", "safe": "s"}, "citations": [], "status": "candidate"}


def answer(rule):
    return json.dumps({"rule": rule, "reason": None if rule else "library internal"})


class RuleDraftTests(unittest.TestCase):
    def test_prompt_carries_the_card_and_the_rule_format(self):
        prompt = rule_draft.build_prompt(CARD)

        for text in (CARD["cause"], CARD["prevention"], "absent_or_not_in", "built_string", '"rule": null'):
            self.assertIn(text, prompt)

    def test_a_patch_checked_card_brings_what_the_fix_changed(self):
        observation = "The fix passes SafeLoader to every yaml.load call."

        self.assertIn(observation, rule_draft.build_prompt(dict(CARD, fix_observation=observation)))
        self.assertNotIn("fix_observation", rule_draft.build_prompt(CARD))

    def test_a_valid_rule_is_accepted_and_tied_to_the_card(self):
        result = rule_draft.draft_rule(CARD, lambda prompt: answer(YAML_LOAD))

        self.assertEqual(result["rule"], YAML_LOAD)
        self.assertEqual(result["errors"], [])

    def test_a_rule_for_another_cve_is_rejected(self):
        other = dict(YAML_LOAD, cve_ids=["CVE-2099-0001"])

        result = rule_draft.draft_rule(CARD, lambda prompt: answer(other))

        self.assertIsNone(result["rule"])
        self.assertTrue(any("cve_ids" in error for error in result["errors"]))

    def test_no_rule_answers_are_recorded_with_their_reason(self):
        result = rule_draft.draft_rule(CARD, lambda prompt: answer(None))

        self.assertEqual((result["rule"], result["no_rule"], result["attempts"]), (None, "library internal", 1))

    def test_a_failing_rule_is_retried_with_the_reasons(self):
        broken = copy.deepcopy(YAML_LOAD)
        broken["require"] = []
        answers = iter([answer(broken), answer(YAML_LOAD)])
        prompts = []

        def ask(prompt):
            prompts.append(prompt)
            return next(answers)

        result = rule_draft.draft_rule(CARD, ask)

        self.assertEqual((result["rule"], result["attempts"]), (YAML_LOAD, 2))
        self.assertIn("flagged", prompts[1])

    def test_a_rejected_draft_keeps_the_last_answer_for_diagnosis(self):
        broken = dict(YAML_LOAD, call=["load"])

        result = rule_draft.draft_rule(CARD, lambda prompt: answer(broken))

        self.assertIsNone(result["rule"])
        self.assertEqual(result["attempts"], rule_draft.ATTEMPTS)
        self.assertEqual(result["last_answer"]["rule"]["call"], ["load"])

    def test_rules_with_the_same_matcher_are_merged_across_cves(self):
        second = dict(YAML_LOAD, rule_id="yaml-load-other-v1", cve_ids=["CVE-2017-18342"], title="Other title",
                      examples=dict(YAML_LOAD["examples"], vulnerable=["import yaml as y\ny.load(s)\n"]))
        shell = json.loads(json.dumps(YAML_LOAD))
        shell.update(rule_id="other-call-v1", call=["yaml.unsafe_load"], cve_ids=["CVE-2021-0003"])

        merged = rule_draft.merge_rules([YAML_LOAD, second, shell])

        self.assertEqual([rule["rule_id"] for rule in merged], ["other-call-v1", "yaml-load-other-v1"])
        self.assertEqual(merged[1]["cve_ids"], ["CVE-2017-18342", "CVE-2020-1747"])
        self.assertEqual(len(merged[1]["examples"]["vulnerable"]), 2)

    def test_a_rule_with_extra_conditions_is_folded_into_the_broader_rule(self):
        broad = json.loads(json.dumps(YAML_LOAD))
        broad.update(rule_id="torch-load-v1", call=["torch.load"], cve_ids=["CVE-2021-0001"],
                     require=[{"keyword": "weights_only", "absent_or_not_in": [True]}])
        narrow = json.loads(json.dumps(broad))
        narrow.update(cve_ids=["CVE-2021-0002"], require=[{"arg": 0, "is": "non_constant"}] + broad["require"])

        merged = rule_draft.merge_rules([narrow, broad])

        self.assertEqual(len(merged), 1)
        self.assertEqual((merged[0]["require"], merged[0]["cve_ids"]), (broad["require"], ["CVE-2021-0001", "CVE-2021-0002"]))

    def test_different_rules_never_share_an_id(self):
        first = json.loads(json.dumps(YAML_LOAD))
        second = json.loads(json.dumps(YAML_LOAD))
        second.update(cve_ids=["CVE-2021-0009"], require=[{"keyword": "Loader", "absent_or_not_in": ["yaml.BaseLoader"]}])

        ids = [rule["rule_id"] for rule in rule_draft.merge_rules([first, second])]

        self.assertEqual(len(set(ids)), 2)
        self.assertIn("yaml-load-unsafe-loader-cve-2021-0009-v1", ids)

    def test_a_rule_whose_calls_another_rule_covers_with_the_same_conditions_is_folded_into_it(self):
        broad = json.loads(json.dumps(YAML_LOAD))
        broad.update(rule_id="z-broad-v1", call=["yaml.load", "yaml.load_all"], cve_ids=["CVE-2021-0001"])
        narrow = json.loads(json.dumps(YAML_LOAD))
        narrow.update(rule_id="a-narrow-v1", call=["yaml.load"], cve_ids=["CVE-2021-0002"])
        stricter = json.loads(json.dumps(narrow))
        # Different conditions (not a superset of the broad rule's): it reports other calls, so it stays.
        stricter.update(rule_id="b-stricter-v1", require=[{"keyword": "Loader", "absent_or_not_in": ["yaml.BaseLoader"]}],
                        cve_ids=["CVE-2021-0003"])

        merged = rule_draft.merge_rules([narrow, broad, stricter])

        self.assertEqual([rule["rule_id"] for rule in merged], ["b-stricter-v1", "z-broad-v1"])
        self.assertEqual(merged[1]["cve_ids"], ["CVE-2021-0001", "CVE-2021-0002"])


if __name__ == "__main__":
    unittest.main()
