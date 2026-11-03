"""Checking candidate cards against their upstream fix diff (plan: paladin-card-patch-review)."""
import json
import unittest

from paladin import patch_review

CARD = {"cve_id": "CVE-2008-0252", "family": "path_traversal", "packages": ["cherrypy"],
        "title": "Crafted session id escapes the session directory",
        "cause": "The session file path is built from a session id read from a client cookie.",
        "preconditions": ["Sessions are stored as files."],
        "prevention": "Check that the session id has the expected form before building a file path.",
        "limitations": "The sources do not say which characters trigger the traversal.",
        "fixtures": {"risk": "r", "safe": "s"}, "citations": [], "status": "candidate"}

DIFF = """diff --git a/CHANGES.txt b/CHANGES.txt
--- a/CHANGES.txt
+++ b/CHANGES.txt
@@ -1 +1,2 @@
+Fixed session id handling.
diff --git a/tests/test_session.py b/tests/test_session.py
--- a/tests/test_session.py
+++ b/tests/test_session.py
@@ -1 +1,2 @@
+    self.assertRaises(ValueError, sess._get_file_path, '../x')
diff --git a/cherrypy/lib/sessions.py b/cherrypy/lib/sessions.py
--- a/cherrypy/lib/sessions.py
+++ b/cherrypy/lib/sessions.py
@@ -10,3 +10,5 @@
         f = os.path.join(self.storage_path, self.SESSION_PREFIX + self.id)
+        if not os.path.abspath(f).startswith(self.storage_path):
+            raise cherrypy.HTTPError(400, "Invalid session id in cookie.")
         return f
"""


def answer(verdict, observation="The fix rejects a session file path that resolves outside the storage directory.",
           revised=None):
    return json.dumps({"verdict": verdict, "observation": observation, "revised": revised})


REVISED = {"cause": "The session id from a cookie is joined to the storage directory without checking the result.",
           "preconditions": ["Sessions are stored as files."],
           "prevention": "Resolve the session file path and reject it unless it stays inside the storage directory.",
           "limitations": "The fix checks the joined path, not the form of the id."}


class DiffUrlTests(unittest.TestCase):
    def test_commit_and_pull_links_on_github_become_diff_urls(self):
        self.assertEqual(patch_review.diff_url("https://github.com/cherrypy/cherrypy/commit/37b856eba6f2"),
                         "https://github.com/cherrypy/cherrypy/commit/37b856eba6f2.diff")
        self.assertEqual(patch_review.diff_url("https://github.com/lxml/lxml/pull/273/files"),
                         "https://github.com/lxml/lxml/pull/273.diff")

    def test_other_links_are_skipped(self):
        for url in ("https://github.com/gitpython-developers/GitPython/releases/tag/3.1.47",
                    "https://bugs.launchpad.net/horizon/+bug/1982676",
                    "https://github.com.evil.example/a/b/commit/abcdef1",
                    "http://github.com/a/b/commit/abcdef1"):
            self.assertIsNone(patch_review.diff_url(url), url)


class PrepareDiffTests(unittest.TestCase):
    def test_changelog_is_dropped_and_source_comes_before_tests(self):
        text, truncated = patch_review.prepare_diff(DIFF, budget=10_000)

        self.assertNotIn("CHANGES.txt", text)
        self.assertLess(text.index("cherrypy/lib/sessions.py"), text.index("tests/test_session.py"))
        self.assertFalse(truncated)

    def test_a_quoted_path_with_a_space_is_kept(self):
        quoted = DIFF.replace("diff --git a/cherrypy/lib/sessions.py b/cherrypy/lib/sessions.py",
                              'diff --git "a/cherrypy/lib/my sessions.py" "b/cherrypy/lib/my sessions.py"')

        text, _ = patch_review.prepare_diff(quoted, budget=10_000)

        self.assertIn("my sessions.py", text)
        self.assertLess(text.index("my sessions.py"), text.index("tests/test_session.py"))

    def test_a_diff_over_budget_is_cut_and_marked(self):
        text, truncated = patch_review.prepare_diff(DIFF, budget=200)

        self.assertLessEqual(len(text), 200)
        self.assertTrue(truncated)
        self.assertIn("cherrypy/lib/sessions.py", text)


class ValidateTests(unittest.TestCase):
    def setUp(self):
        self.diff, _ = patch_review.prepare_diff(DIFF, budget=10_000)

    def test_an_aligned_answer_in_prose_is_accepted(self):
        self.assertEqual(patch_review.validate_answer(json.loads(answer("aligned")), self.diff), [])

    def test_unknown_verdicts_and_code_are_rejected(self):
        self.assertTrue(patch_review.validate_answer(json.loads(answer("maybe")), self.diff))
        code = answer("aligned", observation="It adds `if not os.path.abspath(f)` before returning.")
        self.assertTrue(patch_review.validate_answer(json.loads(code), self.diff))

    def test_copying_an_added_line_of_the_diff_is_rejected(self):
        copied = answer("aligned", observation="It now raises Invalid session id in cookie. for bad ids")
        copied_line = answer("aligned", observation='raise cherrypy.HTTPError(400, "Invalid session id in cookie.")')

        self.assertEqual(patch_review.validate_answer(json.loads(copied), self.diff), [])
        self.assertTrue(patch_review.validate_answer(json.loads(copied_line), self.diff))

    def test_misaligned_needs_a_revision_and_others_must_not_carry_one(self):
        self.assertTrue(patch_review.validate_answer(json.loads(answer("misaligned")), self.diff))
        self.assertEqual(patch_review.validate_answer(json.loads(answer("misaligned", revised=REVISED)), self.diff), [])
        self.assertTrue(patch_review.validate_answer(json.loads(answer("aligned", revised=REVISED)), self.diff))


class RevisionTests(unittest.TestCase):
    def test_a_corrected_card_follows_the_same_text_rules(self):
        diff, _ = patch_review.prepare_diff(DIFF, budget=10_000)
        copied = dict(REVISED, prevention='raise cherrypy.HTTPError(400, "Invalid session id in cookie.")')

        self.assertEqual(patch_review.validate_revision(REVISED, diff), [])
        self.assertTrue(patch_review.validate_revision(copied, diff))
        self.assertTrue(patch_review.validate_revision(dict(REVISED, title="extra"), diff))

    def test_a_revision_must_keep_the_search_passage_within_the_encoder(self):
        diff, _ = patch_review.prepare_diff(DIFF, budget=10_000)
        long = dict(REVISED, preconditions=["Sessions are stored as files on a shared disk. " * 6] * 4,
                    cause="The session id is joined to the storage path without a check. " * 12)

        self.assertEqual(patch_review.validate_revision(REVISED, diff, CARD), [])
        errors = patch_review.validate_revision(long, diff, CARD)
        self.assertTrue(any("search passage" in error for error in errors), errors)
        self.assertTrue(patch_review.validate_answer(json.loads(answer("misaligned", revised=long)), diff, CARD))


class ReviewTests(unittest.TestCase):
    def diffs(self):
        return [{"url": "https://github.com/cherrypy/cherrypy/commit/37b856e.diff", "text": DIFF}]

    def test_prompt_carries_the_card_and_the_diff_as_data(self):
        prompt = patch_review.build_prompt(CARD, [{"url": "u", "text": "diff body", "truncated": True}])

        for text in (CARD["cause"], CARD["prevention"], "diff body", "truncated", "untrusted"):
            self.assertIn(text, prompt)

    def test_an_aligned_card_is_promoted_with_its_observation(self):
        record = patch_review.review_card(CARD, self.diffs(), lambda prompt: answer("aligned"))

        self.assertEqual((record["outcome"], record["verdict"]), ("patch_checked", "aligned"))
        self.assertIsNone(record["revised"])
        self.assertEqual(record["patches"][0]["sha256"], patch_review.sha256_text(DIFF))
        self.assertNotIn("text", record["patches"][0])

    def test_a_misaligned_card_is_rewritten_and_promoted_only_if_the_recheck_agrees(self):
        answers = iter([answer("misaligned", revised=REVISED), answer("aligned")])
        prompts = []

        def ask(prompt):
            prompts.append(prompt)
            return next(answers)

        record = patch_review.review_card(CARD, self.diffs(), ask)

        self.assertEqual((record["outcome"], record["verdict"], record["recheck"]), ("patch_checked", "misaligned", "aligned"))
        self.assertEqual(record["revised"], REVISED)
        self.assertIn(REVISED["prevention"], prompts[1])

        answers = iter([answer("misaligned", revised=REVISED), answer("misaligned", revised=REVISED)])
        record = patch_review.review_card(CARD, self.diffs(), lambda prompt: next(answers))
        self.assertEqual(record["outcome"], "candidate")

    def test_unrelated_or_missing_diffs_keep_the_card_a_candidate(self):
        record = patch_review.review_card(CARD, self.diffs(), lambda prompt: answer("unrelated"))
        self.assertEqual((record["outcome"], record["verdict"]), ("candidate", "unrelated"))

        record = patch_review.review_card(CARD, [], lambda prompt: self.fail("model called without a diff"))
        self.assertEqual((record["outcome"], record["reason"]), ("candidate", "no_diff"))

    def test_an_invalid_answer_is_retried_then_recorded(self):
        record = patch_review.review_card(CARD, self.diffs(), lambda prompt: "not json")

        self.assertEqual((record["outcome"], record["reason"]), ("candidate", "invalid_answer"))
        self.assertTrue(record["errors"])


if __name__ == "__main__":
    unittest.main()
