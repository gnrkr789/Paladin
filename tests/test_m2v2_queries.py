"""Known-item retrieval queries for candidate cards: sampling and leakage checks."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "eval"))

import m2v2_queries  # noqa: E402

PATTERN = {"pattern_id": "CVE-2024-22195", "family": "xss", "packages": ["jinja2"], "verification_status": "candidate",
           "title": "Attribute keys are not escaped in the xmlattr filter",
           "cause": "The xmlattr filter accepted keys containing spaces.", "preconditions": ["Untrusted keys."],
           "prevention": "Reject attribute keys with spaces before rendering."}


def pattern(cve, family, status="candidate"):
    return dict(PATTERN, pattern_id=cve, family=family, verification_status=status)


class SamplingTests(unittest.TestCase):
    def test_sampling_is_stratified_fixed_and_candidate_only(self):
        patterns = [pattern("CVE-2020-{:04d}".format(i), family) for i, family in
                    enumerate(["xss"] * 12 + ["xxe"] * 3 + ["ssrf"] * 9)]
        patterns.append(pattern("CVE-2019-0001", "xss", status="source_observed"))

        first = m2v2_queries.select_targets(patterns, per_family=8, seed=7)
        second = m2v2_queries.select_targets(list(reversed(patterns)), per_family=8, seed=7)

        self.assertEqual(first, second)
        families = [p["family"] for p in first]
        self.assertEqual((families.count("xss"), families.count("xxe"), families.count("ssrf")), (8, 3, 8))
        self.assertNotIn("CVE-2019-0001", [p["pattern_id"] for p in first])

    def test_already_used_targets_are_excluded_from_a_new_sample(self):
        patterns = [pattern("CVE-2020-{:04d}".format(i), "xss") for i in range(10)]
        used = {"CVE-2020-0000", "CVE-2020-0001", "CVE-2020-0002"}

        chosen = m2v2_queries.select_targets(patterns, per_family=8, seed=7, exclude=used)

        self.assertEqual(len(chosen), 7)
        self.assertTrue(used.isdisjoint(p["pattern_id"] for p in chosen))


class CleanupTests(unittest.TestCase):
    def test_typographic_quotes_and_wrapping_are_normalized_but_nothing_else(self):
        raw = "  “How can’t a user’s upload name escape the folder?” \n"

        self.assertEqual(m2v2_queries.clean_answer(raw), "How can't a user's upload name escape the folder?")
        self.assertEqual(m2v2_queries.clean_answer("Café question?"), "Café question?")


class LeakageTests(unittest.TestCase):
    def errors(self, query):
        return m2v2_queries.query_errors(query, PATTERN)

    def test_a_plain_developer_question_is_accepted(self):
        self.assertEqual(self.errors("How do I render user supplied dictionary keys as HTML attributes in a "
                                     "template without letting a key inject extra attributes?"), [])

    def test_identifiers_package_names_and_card_wording_are_rejected(self):
        for query in ("Is CVE-2024-22195 a risk for my templates?",
                      "How do I safely use Jinja2 attribute rendering with user keys?",
                      "Why does the xmlattr filter accepted keys containing spaces in my app?",
                      "Short?", "Rendering user keys as attributes without injection risks in templates",
                      "How do I render keys — safely as attributes in templates?"):
            with self.subTest(query=query):
                self.assertTrue(self.errors(query))


if __name__ == "__main__":
    unittest.main()
