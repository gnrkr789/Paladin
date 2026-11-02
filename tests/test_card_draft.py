"""Advisory-only card drafting: prompt contents and draft validation (S3, S4)."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from paladin import card_draft

DETAILS = ("In Django 2.2 before 2.2.21, MultiPartParser, UploadedFile, and FieldFile allowed directory "
           "traversal via uploaded files with suitably crafted file names. Built-in upload handlers were not "
           "affected.")
FIX_URL = "https://github.com/django/django/commit/04ac1624bdc2fa737188401757cf95ced122d26d"
DRAFT = {
    "title": "Uploaded file names can escape the storage directory",
    "cause": "Upload handling kept path components from client supplied file names.",
    "preconditions": ["An attacker controls the name of an uploaded file."],
    "prevention": ("Reduce every client supplied file name to a safe base name and reject names that "
                   "are empty, dot only or contain path separators before storage builds a path."),
    "limitations": "The advisory does not list every storage backend that was affected.",
    "fixtures": {"risk": "An upload named ../../x lands outside the upload directory.",
                 "safe": "An upload named report.pdf is stored under the upload directory."},
    "citations": [{"source": "GHSA-rxjp-mfm9-w4wr",
                   "quote": "allowed directory traversal via uploaded files with suitably crafted file names"}],
}


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


class DraftTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.roots = {"pysec": root / "pysec", "ghsa": root / "ghsa", "cvelist": root / "cvelist"}
        ghsa_path = "advisories/github-reviewed/2021/05/GHSA-rxjp-mfm9-w4wr/GHSA-rxjp-mfm9-w4wr.json"
        ghsa_sha = write(self.roots["ghsa"] / ghsa_path, json.dumps(
            {"id": "GHSA-rxjp-mfm9-w4wr", "summary": "Path Traversal in Django", "details": DETAILS}))
        cve_path = "cves/2021/31xxx/CVE-2021-31542.json"
        cve_sha = write(self.roots["cvelist"] / cve_path, json.dumps(
            {"containers": {"cna": {"descriptions": [{"lang": "en", "value": DETAILS}]}}}))
        self.case = {
            "cve_id": "CVE-2021-31542", "packages": ["django"], "family": "path_traversal", "cwe_ids": ["CWE-22"],
            "fix_references": [FIX_URL],
            "advisories": [{"id": "GHSA-rxjp-mfm9-w4wr", "source": "ghsa", "path": ghsa_path, "sha256": ghsa_sha}],
            "cve_record": {"path": cve_path, "sha256": cve_sha, "state": "PUBLISHED"},
        }

    def sources(self):
        return card_draft.source_texts(self.case, self.roots)

    def errors(self, **changes):
        draft = copy.deepcopy(DRAFT)
        draft.update(changes)
        return card_draft.validate_draft(draft, self.sources())

    def test_sources_are_the_advisory_and_cve_texts_at_their_recorded_hashes(self):
        sources = self.sources()

        self.assertEqual([source["id"] for source in sources], ["GHSA-rxjp-mfm9-w4wr", "CVE-2021-31542"])
        self.assertIn("Path Traversal in Django", sources[0]["text"])
        self.assertIn(DETAILS, sources[1]["text"])

    def test_a_changed_source_file_is_refused(self):
        path = self.roots["ghsa"] / self.case["advisories"][0]["path"]
        path.write_text(path.read_text(encoding="utf-8") + " ", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "hash"):
            self.sources()

    def test_prompt_carries_the_advisory_text_and_the_rules_but_no_fix_code(self):
        prompt = card_draft.build_prompt(self.case, self.sources())

        self.assertIn(DETAILS, prompt)
        self.assertIn("path_traversal", prompt)
        self.assertIn("no code", prompt.lower())
        self.assertIn(FIX_URL, prompt)

    def test_a_valid_draft_becomes_a_candidate_card_with_reference_urls(self):
        self.assertEqual(card_draft.validate_draft(DRAFT, self.sources()), [])

        card = card_draft.to_card(DRAFT, self.case, drafter="model-x")

        self.assertEqual(card["cve_id"], "CVE-2021-31542")
        self.assertEqual(card["status"], "candidate")
        self.assertEqual(card["family"], "path_traversal")
        self.assertEqual(card["fix_references"], [FIX_URL])
        self.assertEqual(card["drafter"], "model-x")
        self.assertEqual(card["sources"], [
            {"id": "GHSA-rxjp-mfm9-w4wr", "path": self.case["advisories"][0]["path"],
             "sha256": self.case["advisories"][0]["sha256"]},
            {"id": "CVE-2021-31542", "path": self.case["cve_record"]["path"],
             "sha256": self.case["cve_record"]["sha256"]}])

    def test_quotes_absent_from_the_cited_source_are_rejected(self):
        errors = self.errors(citations=[{"source": "GHSA-rxjp-mfm9-w4wr", "quote": "remote code execution"}])

        self.assertTrue(any("not found" in error for error in errors), errors)

    def test_quotes_from_an_unknown_source_are_rejected(self):
        errors = self.errors(citations=[{"source": "GHSA-zzzz-zzzz-zzzz", "quote": "directory traversal"}])

        self.assertTrue(any("unknown source" in error for error in errors), errors)

    def test_non_ascii_quotes_are_rejected_even_when_the_source_has_them(self):
        path = self.roots["cvelist"] / self.case["cve_record"]["path"]
        path.write_text(json.dumps({"containers": {"cna": {"descriptions": [
            {"lang": "en", "value": "input from the “tgt_env” argument"}]}}}), encoding="utf-8")
        self.case["cve_record"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()

        errors = self.errors(citations=[{"source": "CVE-2021-31542", "quote": "from the “tgt_env”"}])

        self.assertTrue(any("ASCII" in error for error in errors), errors)

    def test_long_quotes_are_rejected(self):
        errors = self.errors(citations=[{"source": "CVE-2021-31542", "quote": DETAILS}])

        self.assertTrue(any("too long" in error for error in errors), errors)

    def test_code_in_any_field_is_rejected(self):
        for field, value in (("prevention", "Use `os.path.basename(name)` here."),
                             ("prevention", "```python\nname = os.path.basename(name)\n```"),
                             ("cause", "name = request.FILES['f'].name"),
                             ("limitations", "def save(name):\n    return name")):
            with self.subTest(value=value):
                self.assertTrue(any("code" in error for error in self.errors(**{field: value})), value)

    def test_api_names_in_prose_are_allowed(self):
        self.assertEqual(self.errors(prevention="Resolve the final path with os.path.realpath() and require it "
                                                "to stay under the storage root."), [])

    def test_drafting_accepts_a_fenced_json_answer_on_the_first_try(self):
        prompts = []

        def ask(prompt):
            prompts.append(prompt)
            return "```json\n" + json.dumps(DRAFT) + "\n```"

        result = card_draft.draft_case(self.case, self.sources(), ask)

        self.assertEqual((result["draft"], result["attempts"], result["errors"]), (DRAFT, 1, []))
        self.assertEqual(len(prompts), 1)

    def test_drafting_retries_once_with_the_rejection_reasons(self):
        bad = dict(DRAFT, prevention="Use `basename(name)`.")
        answers = iter([json.dumps(bad), json.dumps(DRAFT)])
        prompts = []

        def ask(prompt):
            prompts.append(prompt)
            return next(answers)

        result = card_draft.draft_case(self.case, self.sources(), ask)

        self.assertEqual((result["draft"], result["attempts"]), (DRAFT, 2))
        self.assertIn("prevention: looks like code", prompts[1])

    def test_drafting_gives_up_after_the_last_attempt_and_keeps_the_reasons(self):
        result = card_draft.draft_case(self.case, self.sources(), lambda prompt: "not json at all")

        self.assertIsNone(result["draft"])
        self.assertEqual(result["attempts"], 2)
        self.assertTrue(any("JSON" in error for error in result["errors"]), result["errors"])

    def test_non_ascii_missing_fields_and_bad_shapes_are_rejected(self):
        self.assertTrue(self.errors(title="Upload names – traversal"))
        draft = copy.deepcopy(DRAFT)
        del draft["cause"]
        self.assertTrue(card_draft.validate_draft(draft, self.sources()))
        self.assertTrue(self.errors(preconditions=[]))
        self.assertTrue(self.errors(citations=[]))
        self.assertTrue(self.errors(fixtures={"risk": "x"}))
        self.assertTrue(self.errors(extra="field"))
        self.assertTrue(card_draft.validate_draft("not a dict", self.sources()))


if __name__ == "__main__":
    unittest.main()
