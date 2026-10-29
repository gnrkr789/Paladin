"""Runtime identities fail closed before any target execution."""
import hashlib
import importlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout


class CaseRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name)
        self.runtime = importlib.import_module("paladin.case_runtime")
        self.assets = self.root / "assets"
        self.assets.mkdir()
        (self.assets / "Dockerfile").write_bytes(b"FROM fixture\n")
        (self.assets / "observer.py").write_bytes(b"# observer fixture\n")
        (self.assets / "target.py").write_bytes(b"# target fixture\n")
        (self.assets / "trace_grammar.py").write_bytes(b"# grammar fixture\n")
        self.asset_patch = patch("paladin.sandbox_runtime.ASSETS", self.assets)
        self.asset_patch.start()
        self.identity = {"image_id": "sha256:" + "1" * 64,
                         "observer_id": "docker-strace-execve-v4",
                         "build_context_sha256": hashlib.sha256(
                             b"Dockerfile\0FROM fixture\nobserver.py\0# observer fixture\ntarget.py\0# target fixture\n"
                             b"trace_grammar.py\0# grammar fixture\n").hexdigest(),
                         "build_log_sha256": "2" * 64}

    def tearDown(self):
        self.asset_patch.stop()
        self.folder.cleanup()

    def configure(self):
        with patch("paladin.sandbox_runtime.build_runtime", return_value=self.identity) as build:
            result = self.runtime.configure_runtime(self.root)
            build.assert_called_once_with(evidence_dir=None)
        self.assertEqual(result, self.identity)

    def test_configure_and_load_immutable_identity(self):
        self.configure()
        self.assertEqual(self.runtime.load_runtime(self.root), self.identity)

    def test_missing_runtime_does_not_build(self):
        with patch("paladin.sandbox_runtime.build_runtime") as build:
            with self.assertRaisesRegex(ValueError, "runtime_not_configured"):
                self.runtime.load_runtime(self.root)
        build.assert_not_called()

    def test_stale_assets_and_forged_identity_are_rejected(self):
        self.configure()
        (self.assets / "Dockerfile").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "runtime_build_context_changed"):
            self.runtime.load_runtime(self.root)
        for field, value in (("image_id", "paladin:latest"), ("observer_id", "unknown"),
                             ("build_log_sha256", "invalid")):
            damaged = dict(self.identity, **{field: value})
            (self.root / ".paladin" / "runtime.json").write_text(json.dumps(damaged), encoding="ascii")
            with self.assertRaises(ValueError):
                self.runtime.load_runtime(self.root)

    def test_oversized_and_nonregular_state_are_rejected(self):
        self.configure()
        runtime_file = self.root / ".paladin" / "runtime.json"
        runtime_file.write_bytes(b" " * 4097)
        with self.assertRaisesRegex(ValueError, "runtime_state_too_large"):
            self.runtime.load_runtime(self.root)
        runtime_file.unlink()
        runtime_file.mkdir()
        with self.assertRaisesRegex(ValueError, "runtime_path_not_regular"):
            self.runtime.load_runtime(self.root)

    def test_reparse_points_are_rejected(self):
        with patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=0, st_file_attributes=0x400)):
            with self.assertRaisesRegex(ValueError, "runtime_linked_path"):
                self.runtime.load_runtime(self.root)

    def test_duplicate_json_identity_keys_are_rejected(self):
        self.configure()
        raw = json.dumps(self.identity)
        raw = raw[:-1] + ', "image_id": "sha256:' + "3" * 64 + '"}'
        (self.root / ".paladin" / "runtime.json").write_text(raw, encoding="ascii")
        with self.assertRaisesRegex(ValueError, "runtime_invalid_json"):
            self.runtime.load_runtime(self.root)

    def test_python_cache_does_not_change_asset_identity(self):
        self.configure()
        (self.assets / "__pycache__").mkdir()
        (self.assets / "__pycache__" / "observer.pyc").write_bytes(b"cached")
        self.assertEqual(self.runtime.load_runtime(self.root), self.identity)

    def test_build_identity_must_match_current_assets(self):
        damaged = dict(self.identity, build_context_sha256="0" * 64)
        with patch("paladin.sandbox_runtime.build_runtime", return_value=damaged):
            with self.assertRaisesRegex(ValueError, "runtime_build_context_changed"):
                self.runtime.configure_runtime(self.root)
        self.assertFalse((self.root / ".paladin" / "runtime.json").exists())

    def test_cli_lists_both_supported_cves_and_optional_filter(self):
        from paladin.cli import main
        with patch("paladin.case_pipeline.verified_case_references", return_value={"status": "complete", "cases": []}) as refs:
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["cases", "list", "--workspace", str(self.root), "--json"]), 0)
            self.assertEqual([call.args[1] for call in refs.call_args_list], ["CVE-2022-24065", "CVE-2023-5752"])
            refs.reset_mock()
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["cases", "list", "--workspace", str(self.root),
                                       "--cve", "CVE-2023-5752", "--json"]), 0)
            self.assertEqual([call.args[1] for call in refs.call_args_list], ["CVE-2023-5752"])

    def test_cli_explicit_build_and_safe_error_codes(self):
        from paladin.cli import main, _case_error
        self.assertEqual(_case_error(ValueError("runtime_not_configured")), "runtime_not_configured")
        self.assertEqual(_case_error(ValueError("sandbox_docker_failed:untrusted\u001b[0m")), "sandbox_docker_failed")
        self.assertEqual(_case_error(ValueError("untrusted\u001b[0m")), "case_operation_failed")
        with patch("paladin.case_runtime.configure_runtime", return_value=self.identity) as build:
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["cases", "runtime-build", "--workspace", str(self.root), "--json"]), 0)
            build.assert_called_once_with(self.root)
            self.assertEqual(json.loads(output.getvalue())["runtime"], self.identity)


if __name__ == "__main__":
    unittest.main()
