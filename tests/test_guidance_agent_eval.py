"""Evaluation scoring must distinguish a patch from a completed host run."""
import unittest

from eval.guidance_agent_eval import assess_attempt


class GuidanceAgentEvaluationTests(unittest.TestCase):
    def test_success_requires_host_edit_and_all_private_cases(self):
        cases = [{"role": "risk", "pass": True}, {"role": "safe", "pass": True}]
        self.assertEqual(assess_attempt(0, True, False, cases), "success")
        self.assertEqual(assess_attempt(0, False, False, cases), "incomplete")
        self.assertEqual(assess_attempt(1, True, False, cases), "incomplete")
        self.assertEqual(assess_attempt(0, True, True, cases), "incomplete")

    def test_failed_private_behavior_is_not_success(self):
        cases = [{"role": "risk", "pass": True}, {"role": "safe", "pass": False}]
        self.assertEqual(assess_attempt(0, True, False, cases), "failed")
        self.assertEqual(assess_attempt(0, True, False, None), "incomplete")


if __name__ == "__main__":
    unittest.main()
