"""Repair context must retain integration changes beyond card anchors."""
import hashlib
from pathlib import Path
import shutil
import tempfile
import unittest

from paladin import advisory
from paladin.knowledge import _resource
from paladin.guidance import PILOT_IDS, patch_context, valid_patch_hunks

ROOT = Path(__file__).resolve().parents[1]


class PatchContextTests(unittest.TestCase):
    def test_response_budget_preserves_base_guidance(self):
        result = advisory.bounded({"status": "complete", "guidance": {"pattern_id": "CVE-2024-2912"},
                                   "patch_context": {"status": "complete", "patch": "x" * 70000,
                                                     "changed_files": ["y" * 10000]}})
        self.assertEqual(result["status"], "partial")
        self.assertIn("guidance", result)
        self.assertIsNone(result["patch_context"]["patch"])

    def test_incomplete_hunk_is_not_a_complete_patch(self):
        self.assertFalse(valid_patch_hunks("diff --git a/a.py b/a.py\n@@ -1 +1 @@\n-old\n"))
        self.assertFalse(valid_patch_hunks("diff --git a/a.py b/a.py\n@@ -1 +1 @@\n-old\n+new\n+extra\n"))
        self.assertTrue(valid_patch_hunks("diff --git a/a.py b/a.py\n@@ -1 +1 @@\n-old\n+new\n"))

    def test_bento_context_includes_worker_wiring_and_exact_patch(self):
        args = {"pattern_id": "CVE-2024-2912",
                "pack_sha256": hashlib.sha256(_resource("prevention-pack.json")).hexdigest(),
                "guidance_sha256": hashlib.sha256(_resource("guidance-pack.json")).hexdigest(),
                "include_patch_context": True}
        result = advisory.dispatch(ROOT, "get_prevention_guidance", args)
        self.assertEqual(result["status"], "complete", result)
        context = result["patch_context"]
        self.assertIn("src/_bentoml_impl/worker/service.py", context["changed_files"])
        self.assertIn("src/_bentoml_impl/server/app.py", context["changed_files"])
        raw = (ROOT / "data/m0/sources/CVE-2024-2912.patch.patch").read_bytes()
        self.assertEqual(context["patch"], raw.decode("utf-8"))
        self.assertEqual(context["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertFalse(result["human_reviewed"])
        default = advisory.dispatch(ROOT, "get_prevention_guidance", {k: v for k, v in args.items()
                                                                     if k != "include_patch_context"})
        self.assertNotIn("patch_context", default)

    def test_repair_contract_preserves_special_form_values(self):
        from paladin.guidance import repair_constraints
        cookie = " ".join(repair_constraints("CVE-2022-24065"))
        self.assertIn("leading hyphen", cookie)
        self.assertIn("Git", cookie)
        django = " ".join(repair_constraints("CVE-2022-34265"))
        self.assertIn("parentheses", django)

    def test_all_pilot_contexts_are_complete_and_oversize_is_explicit(self):
        # Isolate from legacy case records retained in the developer checkout.
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        shutil.copytree(ROOT / "data", Path(workspace.name) / "data")
        for pattern_id in PILOT_IDS:
            args = {"pattern_id": pattern_id,
                    "pack_sha256": hashlib.sha256(_resource("prevention-pack.json")).hexdigest(),
                    "guidance_sha256": hashlib.sha256(_resource("guidance-pack.json")).hexdigest(),
                    "include_patch_context": True}
            result = advisory.dispatch(Path(workspace.name), "get_prevention_guidance", args)
            self.assertEqual(result["status"], "complete", result)
            self.assertTrue(result["patch_context"]["changed_files"])
            partial = patch_context(ROOT, result["guidance"], max_bytes=1)
            self.assertEqual(partial["status"], "partial")
            self.assertIsNone(partial["patch"])
            self.assertEqual(partial["reason"], "patch_context_byte_limit")


if __name__ == "__main__":
    unittest.main()
