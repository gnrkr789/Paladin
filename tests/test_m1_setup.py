"""M1 behavior contracts: tests use an in-memory service double, not Milvus."""
import contextlib
import copy
import importlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


class MemoryStore:
    version = "2.6.25"
    schema_matches = True
    records_present = True
    calls = []

    def __init__(self, config):
        self.config = config

    def initialize(self):
        self.calls.append("initialize")

    def inspect(self):
        self.calls.append("inspect")
        return {"server_version": self.version, "schema_matches": self.schema_matches,
                "sample_matches": self.records_present, "search_matches": self.records_present}

    def close(self):
        self.calls.append("close")


class M1SetupContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        MemoryStore.calls = []
        MemoryStore.version = "2.6.25"
        MemoryStore.schema_matches = True
        MemoryStore.records_present = True

    def api(self):
        if not (ROOT / "src/paladin/local.py").exists():
            self.fail("M1 setup/doctor implementation is missing")
        return importlib.import_module("paladin.local")

    def configure(self):
        return self.api().setup(self.root, start=False)

    def test_setup_without_start_creates_local_state_but_does_not_claim_db_ready(self):
        result = self.configure()
        self.assertEqual(result["status"], "configured")
        self.assertFalse(result["security_ready"])
        self.assertTrue((self.root / ".paladin/config.toml").is_file())
        self.assertTrue((self.root / ".paladin/metadata.sqlite3").is_file())
        self.assertEqual(MemoryStore.calls, [])

    def test_repeated_setup_preserves_configuration_and_workspace_identity(self):
        self.configure()
        config = self.root / ".paladin/config.toml"
        config.write_text(config.read_text() + "\n# user note\n", encoding="utf-8")
        before = config.read_bytes()
        identity = (self.root / ".paladin/manifest.json").read_bytes()
        self.configure()
        self.assertEqual(config.read_bytes(), before)
        self.assertEqual((self.root / ".paladin/manifest.json").read_bytes(), identity)

    def test_modified_compose_is_not_executed_or_overwritten(self):
        self.configure()
        compose = self.root / ".paladin/compose.yaml"
        compose.write_text("services: {foreign: {image: unsafe}}\n", encoding="utf-8")
        result = self.api().setup(self.root, start=True, runner=lambda *a, **k: self.fail("must not run"))
        self.assertEqual(result["status"], "error")
        self.assertIn("compose_conflict", json.dumps(result))
        self.assertIn("foreign", compose.read_text())

    def test_doctor_without_setup_is_read_only_and_unavailable(self):
        result = self.api().doctor(self.root, store_factory=MemoryStore)
        self.assertEqual(result["status"], "unavailable")
        self.assertFalse((self.root / ".paladin").exists())
        self.assertEqual(MemoryStore.calls, [])

    def test_doctor_reports_each_component_and_does_not_initialize_db(self):
        self.configure()
        result = self.api().doctor(self.root, store_factory=MemoryStore)
        self.assertEqual(result["status"], "ready")
        for name in ["configuration", "local_metadata", "milvus", "schema", "embedding", "corpus", "search"]:
            self.assertIn(name, result["checks"])
        self.assertNotIn("initialize", MemoryStore.calls)
        self.assertFalse(result["security_ready"])
        self.assertEqual(result["checks"]["embedding"]["mode"], "diagnostic_only")

    def test_disconnected_database_is_unavailable_not_safe(self):
        self.configure()
        def disconnected(config):
            raise ConnectionError("database offline")
        result = self.api().doctor(self.root, store_factory=disconnected)
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["checks"]["milvus"]["status"], "error")
        self.assertFalse(result["security_ready"])

    def test_schema_mismatch_is_not_reported_ready(self):
        self.configure()
        MemoryStore.schema_matches = False
        result = self.api().doctor(self.root, store_factory=MemoryStore)
        self.assertEqual(result["status"], "degraded")
        self.assertEqual(result["checks"]["schema"]["status"], "error")

    def test_missing_diagnostic_corpus_is_not_reported_ready(self):
        self.configure()
        MemoryStore.records_present = False
        result = self.api().doctor(self.root, store_factory=MemoryStore)
        self.assertEqual(result["status"], "degraded")
        self.assertEqual(result["checks"]["corpus"]["status"], "error")

    def test_wrong_server_version_is_not_reported_ready(self):
        self.configure()
        MemoryStore.version = "0.0.0"
        result = self.api().doctor(self.root, store_factory=MemoryStore)
        self.assertEqual(result["status"], "degraded")
        self.assertEqual(result["checks"]["milvus"]["status"], "error")

    def test_remote_endpoint_is_rejected_before_connecting(self):
        self.configure()
        config = self.root / ".paladin/config.toml"
        config.write_text(config.read_text().replace("127.0.0.1", "remote.example"), encoding="utf-8")
        result = self.api().doctor(self.root, store_factory=lambda c: self.fail("must not connect"))
        self.assertEqual(result["status"], "unavailable")
        self.assertIn("loopback", json.dumps(result))

    def test_local_manifest_tampering_is_reported(self):
        self.configure()
        path = self.root / ".paladin/manifest.json"
        manifest = json.loads(path.read_text())
        manifest["embedding_id"] = "other-model"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        result = self.api().doctor(self.root, store_factory=MemoryStore)
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["checks"]["local_metadata"]["status"], "error")

    def test_wrong_config_value_type_returns_diagnostic_instead_of_traceback(self):
        self.configure()
        path = self.root / ".paladin/config.toml"
        path.write_text(path.read_text().replace('uri = "http://127.0.0.1:19530"', 'uri = 123'), encoding="utf-8")
        result = self.api().doctor(self.root, store_factory=lambda c: self.fail("must not connect"))
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["checks"]["configuration"]["status"], "error")

    def test_docker_failure_never_initializes_sample(self):
        self.configure()
        import subprocess
        def failed(*a, **k):
            raise subprocess.CalledProcessError(1, ["docker"], stderr="daemon unavailable")
        result = self.api().setup(self.root, runner=failed, store_factory=MemoryStore)
        self.assertEqual(result["status"], "error")
        self.assertNotIn("initialize", MemoryStore.calls)

    def test_successful_setup_then_doctor_inspects_the_initialized_database(self):
        import subprocess
        result = self.api().setup(self.root, runner=lambda *a, **k: subprocess.CompletedProcess(a, 0), store_factory=MemoryStore)
        self.assertEqual(result["status"], "ready")
        self.assertIn("initialize", MemoryStore.calls)
        self.assertIn("inspect", MemoryStore.calls)

    def test_diagnostic_embedding_is_local_stable_and_normalized(self):
        api = self.api()
        a = api.diagnostic_embedding("path upload storage")
        self.assertEqual(a, api.diagnostic_embedding("path upload storage"))
        self.assertEqual(len(a), 64)
        self.assertAlmostEqual(sum(v * v for v in a), 1.0)
        self.assertNotEqual(a, api.diagnostic_embedding("sql database query"))

    def test_cli_doctor_returns_nonzero_json_when_not_configured(self):
        self.api()
        cli = importlib.import_module("paladin.cli")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cli.main(["doctor", "--workspace", str(self.root), "--json"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue())["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
