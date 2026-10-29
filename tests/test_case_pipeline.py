"""Unit-only observer fixtures exercise authenticated case promotion and reuse."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from paladin.candidate_scan import scan_project
from paladin.case_pipeline import run_case, verified_case_references
from tests.test_case_verification import RUNTIME, SOURCE, mocked_observations


class CasePipelineTests(unittest.TestCase):
    def test_candidate_repair_verify_promote_and_retrieve(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            project, workspace = root / "project", root / "workspace"
            (project / "cookiecutter").mkdir(parents=True)
            (project / "cookiecutter/vcs.py").write_bytes(SOURCE)
            workspace.mkdir()
            candidates = scan_project(project)["candidates"]
            self.assertEqual(len(candidates), 1)
            with patch("paladin.case_pipeline.load_runtime", return_value=RUNTIME), patch(
                    "paladin.sandbox_runtime.run_observed", side_effect=mocked_observations) as observer:
                result = run_case(workspace, project, candidates[0]["candidate_id"])
                refs = verified_case_references(workspace, "CVE-2022-24065")
                reused = run_case(workspace, project, candidates[0]["candidate_id"])
                self.assertTrue(reused["reused"])
                self.assertEqual(reused["case"]["case_id"], result["case"]["case_id"])
                self.assertEqual(observer.call_count, 2)
            self.assertEqual(result["status"], "promoted", result)
            self.assertFalse(result["case"]["human_reviewed"])
            self.assertEqual((project / "cookiecutter/vcs.py").read_bytes(), SOURCE)
            self.assertEqual(refs["status"], "complete")
            self.assertEqual(refs["cases"][0]["case_id"], result["case"]["case_id"])
            path = workspace / ".paladin/case-evidence" / (result["case"]["evidence_sha256"] + ".json")
            evidence = json.loads(path.read_text(encoding="ascii"))
            self.assertEqual(evidence["checks"]["safe_after_passed"], True)
            self.assertEqual(evidence["runtime"], RUNTIME)
            from paladin.case_auth import verify_evidence
            self.assertTrue(verify_evidence(workspace, evidence))
            path.write_text("{}", encoding="ascii")
            with patch("paladin.case_pipeline.load_runtime", return_value=RUNTIME):
                refs = verified_case_references(workspace, "CVE-2022-24065")
            self.assertEqual(refs["status"], "partial")
            self.assertEqual(refs["cases"], [])

    def test_rehashed_evidence_and_case_record_cannot_replace_host_signature(self):
        import hashlib
        import sqlite3
        from contextlib import closing
        from paladin.case_auth import verify_evidence

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            project, workspace = root / "project", root / "workspace"
            (project / "cookiecutter").mkdir(parents=True)
            (project / "cookiecutter/vcs.py").write_bytes(SOURCE)
            workspace.mkdir()
            candidate = scan_project(project)["candidates"][0]
            with patch("paladin.case_pipeline.load_runtime", return_value=RUNTIME), patch(
                    "paladin.sandbox_runtime.run_observed", side_effect=mocked_observations):
                result = run_case(workspace, project, candidate["candidate_id"])
            state = workspace / ".paladin"
            path = state / "case-evidence" / (result["case"]["evidence_sha256"] + ".json")
            evidence = json.loads(path.read_text(encoding="ascii"))
            evidence["after"]["observations"][0]["calls"][0]["argv"][-1] = "--changed-option"
            raw = json.dumps(evidence, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")
            digest = hashlib.sha256(raw).hexdigest()
            (path.parent / (digest + ".json")).write_bytes(raw)
            record = {key: value for key, value in result["case"].items() if key != "case_id"}
            record["evidence_sha256"] = digest
            content = json.dumps(record, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
            case_id = hashlib.sha256(content.encode("ascii")).hexdigest()
            # Model direct disk write access, including bypass of database immutability.
            with closing(sqlite3.connect(state / "cases.sqlite3")) as database, database:
                database.execute("DROP TRIGGER verified_cases_no_update")
                database.execute("UPDATE verified_cases SET case_id = ?, content = ?", (case_id, content))
            self.assertFalse(verify_evidence(workspace, evidence))
            with patch("paladin.case_pipeline.load_runtime", return_value=RUNTIME):
                refs = verified_case_references(workspace, "CVE-2022-24065")
            self.assertEqual(refs, {"status": "partial", "cases": []})

    def test_legacy_verified_record_is_not_exposed(self):
        import hashlib
        from paladin.case_store import promote_case
        with tempfile.TemporaryDirectory() as folder:
            workspace = Path(folder)
            state = workspace / ".paladin"
            (state / "case-evidence").mkdir(parents=True)
            evidence = {"verifier_id": "mercurial-checkout-local-probe-v1",
                        "before_sha256": "a" * 64, "after_sha256": "b" * 64,
                        "checks": {key: True for key in ("before_risk_observed", "after_risk_blocked",
                                                         "safe_before_passed", "safe_after_passed")}}
            raw = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("ascii")
            digest = hashlib.sha256(raw).hexdigest()
            (state / "case-evidence" / (digest + ".json")).write_bytes(raw)
            promote_case(state / "cases.sqlite3", {
                "candidate_id": "c" * 64, "cve_id": "CVE-2022-24065",
                "rule_id": "CVE-2022-24065:mercurial-checkout-v1", "project_identity": "legacy-project",
                "verifier_id": evidence["verifier_id"], "before_sha256": "a" * 64,
                "after_sha256": "b" * 64, "evidence_sha256": digest,
                **evidence["checks"], "human_reviewed": False})
            refs = verified_case_references(workspace, "CVE-2022-24065")
            self.assertEqual(refs, {"status": "partial", "cases": []})
            import shutil
            from paladin import advisory
            from paladin.knowledge import _resource, load_pack
            source_root = Path(__file__).resolve().parents[1]
            pattern = next(item for item in load_pack()["patterns"] if item["pattern_id"] == "CVE-2022-24065")
            for entry in pattern["evidence"]:
                destination = workspace / entry["snapshot_path"]
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_root / entry["snapshot_path"], destination)
            result = advisory.dispatch(workspace, "get_prevention_guidance", {
                "pattern_id": "CVE-2022-24065",
                "pack_sha256": hashlib.sha256(_resource("prevention-pack.json")).hexdigest(),
                "guidance_sha256": hashlib.sha256(_resource("guidance-pack.json")).hexdigest()})
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["verified_case_references"], [])

    def test_unknown_candidate_and_unmodified_source_never_promote(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            project, workspace = root / "project", root / "workspace"
            (project / "cookiecutter").mkdir(parents=True)
            (project / "cookiecutter/vcs.py").write_bytes(SOURCE)
            workspace.mkdir()
            with self.assertRaises(ValueError):
                run_case(workspace, project, "0" * 64)
            self.assertFalse((workspace / ".paladin/cases.sqlite3").exists())


if __name__ == "__main__":
    unittest.main()
