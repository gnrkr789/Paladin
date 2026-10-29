"""Unit seams bind source bytes to mocked external observer outcomes."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from paladin.candidate_scan import scan_project

from paladin.case_verification import PROBE_CASES, derive_checks, propose_repair, verify_case
from tests.observer_fixtures import observed_row


SOURCE = b'''import os
import subprocess
from cookiecutter.exceptions import RepositoryCloneFailed, RepositoryNotFound, UnknownRepoType, VCSNotInstalled
from cookiecutter.utils import make_sure_path_exists, prompt_and_delete
def identify_repo(url):
    return ("hg" if url.startswith("hg+") else "git"), url[3:]
def is_vcs_installed(kind):
    return True
def clone(repo_url, checkout=None, clone_to_dir=".", no_input=False):
    repo_type, repo_url = identify_repo(repo_url)
    subprocess.check_output([repo_type, "clone", repo_url], cwd=clone_to_dir)
    if checkout is not None:
        subprocess.check_output([repo_type, "checkout", checkout], cwd=clone_to_dir)
    return clone_to_dir
'''


RUNTIME = {"image_id": "sha256:" + "a" * 64, "observer_id": "docker-strace-execve-v3",
           "build_context_sha256": "b" * 64, "build_log_sha256": "c" * 64}


def mocked_observations(source_bytes, image_id, cases, evidence_dir=None, *, adapter="cookiecutter"):
    """Supply unit-only OS-observation fixtures; no target or Docker executes."""
    repaired = b"*(['--'] if " in source_bytes or b"'--rev=' + " in source_bytes
    rows = [observed_row(adapter, case, repaired) for case in cases]
    return {"observations": rows,
            "observer": {"id": RUNTIME["observer_id"], "image_id": image_id, "adapter": adapter,
                         "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
                         "target_uid": 65534, "target_cap_eff": 0, "trace_owner_uid": 0,
                         "trace_mode": "0o600", "target_stdout_used": False,
                         "boundary": {"network": "none", "rootfs_readonly": True, "host_mounts": False}}}


class CaseVerificationTests(unittest.TestCase):
    def test_claimed_flags_cannot_override_captured_calls(self):
        cases = [dict(kind=kind, value=value, role=role) for kind, value, role in PROBE_CASES]
        output = mocked_observations(SOURCE, RUNTIME["image_id"], cases)
        for row in output["observations"]:
            row.update(protected=True, exposed=False)
        checks = derive_checks(output, output)
        self.assertTrue(checks["before_risk_observed"])
        self.assertFalse(checks["after_risk_blocked"])
        self.assertFalse(checks["safe_after_passed"])
    def test_before_after_verification_and_source_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            before, after = root / "before", root / "after"
            for directory in (before, after):
                (directory / "cookiecutter").mkdir(parents=True)
                (directory / "cookiecutter/vcs.py").write_bytes(SOURCE)
            candidate = scan_project(before)["candidates"][0]
            proposal = propose_repair(before, after, candidate)
            self.assertNotEqual(proposal["after_sha256"], candidate["source_sha256"])
            with patch("paladin.sandbox_runtime.run_observed", side_effect=mocked_observations) as observer:
                result = verify_case(before, after, candidate, runtime=RUNTIME)
            self.assertEqual(observer.call_count, 2)
            self.assertEqual(observer.call_args_list[0].args[:2], (SOURCE, RUNTIME["image_id"]))
            self.assertEqual(result["status"], "verified", result)
            self.assertTrue(result["record"]["before_risk_observed"])
            self.assertTrue(result["record"]["after_risk_blocked"])
            self.assertTrue(result["record"]["safe_after_passed"])
            self.assertFalse(result["record"]["human_reviewed"])
            with patch("paladin.sandbox_runtime.run_observed") as observer:
                with self.assertRaisesRegex(ValueError, "verification_candidate_binding_mismatch"):
                    verify_case(before, after, {**candidate, "line": candidate["line"] + 1}, runtime=RUNTIME)
                observer.assert_not_called()
            (before / candidate["path"]).write_bytes(SOURCE + b"# changed\n")
            with self.assertRaises(ValueError):
                verify_case(before, after, candidate, runtime=RUNTIME)

    def test_missing_runtime_rejects_source_before_any_target_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            before, after = root / "before", root / "after"
            malicious = SOURCE + b"print('{\"outcomes\": []}')\nraise SystemExit(0)\n"
            for directory in (before, after):
                (directory / "cookiecutter").mkdir(parents=True)
                (directory / "cookiecutter/vcs.py").write_bytes(malicious)
            candidate = scan_project(before)["candidates"][0]
            propose_repair(before, after, candidate)
            with patch("paladin.sandbox_runtime.run_observed") as observer:
                with self.assertRaisesRegex(ValueError, "sandbox_runtime_not_configured"):
                    verify_case(before, after, candidate)
                observer.assert_not_called()

    def test_hardlinked_copy_never_changes_original(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            before, after = root / "before", root / "after"
            for directory in (before, after):
                (directory / "cookiecutter").mkdir(parents=True)
            original = before / "cookiecutter/vcs.py"
            original.write_bytes(SOURCE)
            try:
                os.link(original, after / "cookiecutter/vcs.py")
            except OSError as exc:
                self.skipTest(str(exc))
            candidate = {"path": "cookiecutter/vcs.py", "source_sha256": hashlib.sha256(SOURCE).hexdigest(),
                         "candidate_id": "a" * 64, "rule_id": "CVE-2022-24065:mercurial-checkout-v1",
                         "cve_id": "CVE-2022-24065"}
            with self.assertRaisesRegex(ValueError, "hardlinked_project_copies"):
                propose_repair(before, after, candidate)
            self.assertEqual(original.read_bytes(), SOURCE)

    def test_unchanged_or_scope_escape_cannot_be_promoted(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            candidate = {"path": "../outside.py", "source_sha256": "a" * 64,
                         "candidate_id": "b" * 64, "rule_id": "CVE-2022-24065:mercurial-checkout-v1",
                         "cve_id": "CVE-2022-24065"}
            with self.assertRaises(ValueError):
                propose_repair(root, root, candidate)


if __name__ == "__main__":
    unittest.main()
