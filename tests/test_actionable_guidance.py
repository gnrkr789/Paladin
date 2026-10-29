"""Contracts for conditional, source-pinned guidance candidates."""
import hashlib
import copy
import json
import os
from pathlib import Path
from pathlib import PurePath
import re
import shutil
from urllib.parse import urlsplit
import sys
import tempfile
import unittest
from unittest.mock import patch

from paladin import advisory
from paladin import guidance as guidance_api
from paladin.knowledge import _resource, load_pack


ROOT = Path(__file__).resolve().parents[1]
PILOT_IDS = {
    "CVE-2021-31542", "CVE-2022-34265", "CVE-2024-11168",
    "CVE-2022-24065", "CVE-2024-2912",
}


class GuidanceContracts(unittest.TestCase):
    def args(self, pattern_id):
        guidance_path = ROOT / "src/paladin/resources/guidance-pack.json"
        guidance_sha = hashlib.sha256(guidance_path.read_bytes()).hexdigest() if guidance_path.exists() else "0" * 64
        return {
            "pattern_id": pattern_id,
            "pack_sha256": hashlib.sha256(_resource("prevention-pack.json")).hexdigest(),
            "guidance_sha256": guidance_sha,
        }

    def test_s1_five_families_return_conditional_bounded_guidance(self):
        pack = load_pack()
        families = {p["pattern_id"]: p["family"] for p in pack["patterns"]}
        self.assertEqual(len({families[pid] for pid in PILOT_IDS}), 5)
        # A workspace without a case store: the developer checkout retains legacy
        # case records whose exclusion correctly reports a partial case status.
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        shutil.copytree(ROOT / "data", Path(workspace.name) / "data")
        for pattern_id in PILOT_IDS:
            with self.subTest(pattern_id=pattern_id):
                result = advisory.dispatch(Path(workspace.name), "get_prevention_guidance", self.args(pattern_id))
                self.assertEqual(result["status"], "complete", result)
                self.assertEqual(result["applicability"], "must_verify_target_facts")
                self.assertEqual(result["guidance"]["pattern_id"], pattern_id)
                for key in ("cause", "target_facts", "fix_steps", "preserve", "checks", "limitations", "provenance", "support"):
                    self.assertTrue(result["guidance"][key])
                support = result["guidance"]["support"]
                self.assertTrue(support["cause"])
                for field in ("target_facts", "fix_steps", "preserve", "checks", "limitations"):
                    self.assertEqual(len(support[field]), len(result["guidance"][field]))
                    self.assertTrue(all(refs for refs in support[field]))
                self.assertFalse(result["human_reviewed"])
                self.assertFalse(result["security_ready"])
                self.assertEqual(result["review_state"], "candidate")
                self.assertLessEqual(len(json.dumps(advisory.tool_result(result)).encode()), 65536)

    def test_s2_gaps_are_named_without_applicability_claim(self):
        args = self.args("CVE-2021-31542")
        with tempfile.TemporaryDirectory() as empty:
            missing = advisory.dispatch(Path(empty), "get_prevention_guidance", args)
        self.assertEqual(missing["status"], "unavailable")
        self.assertEqual(missing["gaps"], ["source_content_unavailable"])
        self.assertNotIn("guidance", missing)
        pack = load_pack()
        pack["patterns"][0]["patch_alignment"] = "conflicting"
        with patch("paladin.knowledge.load_pack", return_value=pack):
            conflict = advisory.dispatch(ROOT, "get_prevention_guidance", args)
        self.assertEqual(conflict["gaps"], ["source_claim_not_aligned"])
        self.assertNotIn("applicability", conflict)
        complete = advisory.dispatch(ROOT, "get_prevention_guidance", args)
        self.assertEqual(complete["missing_target_facts"], complete["guidance"]["target_facts"])
        self.assertNotIn("applicable", complete)
        unknown = advisory.dispatch(ROOT, "get_prevention_guidance", self.args("CVE-9999-99999"))
        self.assertEqual(unknown["gaps"], ["unknown_guidance_pattern"])
        self.assertNotIn("guidance", unknown)

    def test_s3_truncated_excerpt_does_not_promote_guidance(self):
        args = self.args("CVE-2021-31542")
        evidence = advisory.dispatch(ROOT, "get_pattern_evidence", {
            "pattern_id": args["pattern_id"], "pack_sha256": args["pack_sha256"],
            "include_excerpt": True, "max_excerpt_bytes": 32,
        })
        self.assertEqual(evidence["status"], "partial")
        self.assertTrue(any(item["reason"] == "excerpt_byte_limit" for item in evidence["omissions"]))
        guidance = advisory.dispatch(ROOT, "get_prevention_guidance", args)
        self.assertFalse(guidance["promotion_eligible"])
        self.assertFalse(guidance["human_reviewed"])
        self.assertEqual(guidance["verification_status"], "source_observed")

    def test_s4_changed_identity_or_snapshot_fails_closed(self):
        args = self.args("CVE-2021-31542")
        old = advisory.dispatch(ROOT, "get_prevention_guidance", {**args, "guidance_sha256": "0" * 64})
        self.assertEqual((old["status"], old["reason"]), ("unsupported", "guidance_revision_mismatch"))
        self.assertNotIn("guidance", old)
        pack = load_pack()
        pack["patterns"][0]["evidence"][0]["sha256"] = "0" * 64
        with patch("paladin.knowledge.load_pack", return_value=pack):
            changed = advisory.dispatch(ROOT, "get_prevention_guidance", args)
        self.assertEqual(changed["gaps"], ["source_content_changed"])
        self.assertNotIn("guidance", changed)
        withdrawn = load_pack()
        withdrawn["patterns"][0]["record_state"] = "REJECTED"
        with patch("paladin.knowledge.load_pack", return_value=withdrawn):
            result = advisory.dispatch(ROOT, "get_prevention_guidance", args)
        self.assertEqual(result["gaps"], ["source_claim_not_aligned"])
        self.assertNotIn("guidance", result)

    def test_s4_changed_guidance_bytes_fail_pack_lock(self):
        raw = _resource("guidance-pack.json")
        original = guidance_api._resource

        def changed(name):
            return raw + b" " if name == "guidance-pack.json" else original(name)

        with patch("paladin.guidance._resource", side_effect=changed):
            with self.assertRaisesRegex(ValueError, "guidance_hash_mismatch"):
                guidance_api.load_guidance()

    def test_s2_patch_anchor_outside_pinned_source_is_a_gap(self):
        claims = copy.deepcopy(guidance_api.load_guidance())
        claims["claims"][0]["patch_lines"] = {"start_line": 1, "end_line": 2}
        with patch("paladin.guidance.load_guidance", return_value=claims):
            result = advisory.dispatch(ROOT, "get_prevention_guidance", self.args("CVE-2021-31542"))
        self.assertEqual(result["gaps"], ["guidance_anchor_outside_evidence"])
        self.assertNotIn("guidance", result)
        claims = copy.deepcopy(guidance_api.load_guidance())
        claims["claims"][0]["support"]["cause"] = ["cve:9999-9999"]
        with patch("paladin.guidance.load_guidance", return_value=claims):
            result = advisory.dispatch(ROOT, "get_prevention_guidance", self.args("CVE-2021-31542"))
        self.assertEqual(result["gaps"], ["guidance_support_outside_source"])
        self.assertNotIn("guidance", result)
        claims = copy.deepcopy(guidance_api.load_guidance())
        claims["claims"][0]["support"]["fix_steps"].pop()
        with patch("paladin.guidance.load_guidance", return_value=claims):
            result = advisory.dispatch(ROOT, "get_prevention_guidance", self.args("CVE-2021-31542"))
        self.assertEqual(result["gaps"], ["guidance_support_count_mismatch"])
        self.assertNotIn("guidance", result)
        claims = copy.deepcopy(guidance_api.load_guidance())
        claims["claims"][0]["support"]["cause"] = ["patch:30-35"]
        with patch("paladin.guidance.load_guidance", return_value=claims):
            result = advisory.dispatch(ROOT, "get_prevention_guidance", self.args("CVE-2021-31542"))
        self.assertEqual(result["gaps"], ["guidance_support_outside_anchor"])
        self.assertNotIn("guidance", result)

    def test_s5_boundary_examples_do_not_count_as_upstream_fixture_approval(self):
        def upload_name(name, parent):
            if name != os.path.basename(name) or name in {"", ".", ".."} or ".." in PurePath(parent).parts:
                raise ValueError("unsafe upload path")
            return str(PurePath(parent) / name)

        def sanitized_filename(name):
            clean = re.sub(r"(?u)[^-\w.]", "", str(name).strip().replace(" ", "_"))
            if clean in {"", ".", ".."}:
                raise ValueError("unsafe normalized filename")
            return clean

        def structural_arg(value):
            if not re.fullmatch(r"[\w\-_()]+", value):
                raise ValueError("unsafe SQL structure")
            return value

        def checkout_argv(repo_type, target):
            return [repo_type, "checkout", *(["--"] if repo_type == "hg" else []), target]

        def main_media_type(is_main, value):
            media_type = value.split(";")[0].strip()
            if is_main and media_type == "application/vnd.bentoml+pickle":
                raise ValueError("pickle rejected")
            return media_type

        for action in [lambda: upload_name("../secret", "uploads"),
                       lambda: upload_name("ok.txt", "uploads/../outside"),
                       lambda: sanitized_filename("???"),
                       lambda: sanitized_filename("$.$.$"),
                       lambda: structural_arg("year); DROP TABLE x;--"),
                       lambda: urlsplit("scheme://user@[127.0.0.1]/path"),
                       lambda: main_media_type(True, "application/vnd.bentoml+pickle; charset=utf-8")]:
            with self.assertRaises(ValueError):
                action()
        self.assertEqual(upload_name("ok.txt", "uploads/2026"), str(PurePath("uploads/2026/ok.txt")))
        self.assertEqual(sanitized_filename("ok file.txt"), "ok_file.txt")
        self.assertEqual(structural_arg("year"), "year")
        self.assertEqual(urlsplit("scheme://user@[::1]/path").hostname, "::1")
        self.assertEqual(urlsplit("scheme://user@[v6a.ip]/path").hostname, "v6a.ip")
        self.assertEqual(checkout_argv("hg", "--config=unsafe"), ["hg", "checkout", "--", "--config=unsafe"])
        self.assertEqual(checkout_argv("hg", "stable"), ["hg", "checkout", "--", "stable"])
        self.assertEqual(main_media_type(True, "application/json"), "application/json")
        result = advisory.dispatch(ROOT, "get_prevention_guidance", self.args("CVE-2021-31542"))
        self.assertEqual(result["fixture_status"], "illustrative_only_upstream_not_executed")
        self.assertFalse(result["promotion_eligible"])


class GuidanceMcpContracts(unittest.IsolatedAsyncioTestCase):
    async def test_s1_real_mcp_worker_returns_pinned_candidate(self):
        from mcp import Client, StdioServerParameters

        pattern_id = "CVE-2022-24065"
        args = GuidanceContracts().args(pattern_id)
        async with Client(StdioServerParameters(command=sys.executable,
                          args=["-B", "-m", "paladin.cli", "mcp", "--workspace", str(ROOT)])) as client:
            result = await client.call_tool("get_prevention_guidance", args)
            self.assertFalse(result.is_error)
            card = result.structured_content
            self.assertEqual(card["guidance"]["pattern_id"], pattern_id)
            self.assertFalse(card["security_ready"])
            self.assertFalse(card["promotion_eligible"])

    async def test_s2_unsupported_text_rejected_before_guidance_access(self):
        from mcp import Client, StdioServerParameters

        args = GuidanceContracts().args("CVE-2021-31542")
        args["pattern_id"] = "CVE-2021-31542\ud55c"
        async with Client(StdioServerParameters(command=sys.executable,
                          args=["-B", "-m", "paladin.cli", "mcp", "--workspace", str(ROOT)])) as client:
            result = await client.call_tool("get_prevention_guidance", args)
            self.assertTrue(result.is_error)
            self.assertEqual(result.structured_content["status"], "invalid_request")


if __name__ == "__main__":
    unittest.main()
