"""Target-created evidence must not authenticate as host-observed evidence."""
import tempfile
from pathlib import Path
import unittest

from paladin.case_auth import sign_evidence, verify_evidence


class CaseAuthTests(unittest.TestCase):
    def test_host_signature_binds_all_evidence_and_workspace_key(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            first, second = root / "first", root / "second"
            first.mkdir()
            second.mkdir()
            evidence = {"verifier_id": "observer-v3", "checks": {"passed": True}, "source_sha256": "a" * 64}
            signed = sign_evidence(first, evidence)
            self.assertTrue(verify_evidence(first, signed))
            self.assertFalse(verify_evidence(second, signed))
            signed["checks"]["passed"] = False
            self.assertFalse(verify_evidence(first, signed))

    def test_unsigned_or_target_supplied_auth_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = Path(folder)
            self.assertFalse(verify_evidence(workspace, {"checks": {"passed": True}}))
            fake = {"checks": {"passed": True}, "auth": {"kind": "host-hmac-v1", "key_id": "a" * 64, "signature": "b" * 64}}
            self.assertFalse(verify_evidence(workspace, fake))


if __name__ == "__main__":
    unittest.main()
