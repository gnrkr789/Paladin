"""M2 contracts: source-qualified advisory packs and local semantic indexing."""
import copy
import importlib
import json
from pathlib import Path
import tempfile
import unittest

import numpy as np

ROOT = Path(__file__).resolve().parents[1]


class M2Contracts(unittest.TestCase):
    def api(self, name="knowledge"):
        if not (ROOT / "src/paladin" / (name + ".py")).exists():
            self.fail("M2 implementation is missing: " + name)
        return importlib.import_module("paladin." + name)

    def pack(self):
        return self.api().load_pack()

    def test_pack_has_thirty_distinct_source_qualified_advisories(self):
        pack = self.pack()
        self.assertEqual(len(pack["patterns"]), 30)
        self.assertEqual(len({p["cve_id"] for p in pack["patterns"]}), 30)
        self.assertTrue(all(not p["enforcement_enabled"] for p in pack["patterns"]))

    def test_m0_mismatched_references_remain_excluded(self):
        ids = {p["cve_id"] for p in self.pack()["patterns"]}
        self.assertTrue(ids.isdisjoint({"CVE-2023-24329", "CVE-2024-5998"}))

    def test_duplicate_pattern_is_rejected(self):
        pack = self.pack()
        pack["patterns"][1] = copy.deepcopy(pack["patterns"][0])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.api().validate_pack(pack)

    def test_rejected_record_is_not_searchable(self):
        pack = self.pack()
        pack["patterns"][0]["record_state"] = "REJECTED"
        with self.assertRaises(ValueError):
            self.api().validate_pack(pack)

    def test_unaligned_patch_is_not_searchable(self):
        pack = self.pack()
        pack["patterns"][0]["patch_alignment"] = "unresolved"
        with self.assertRaises(ValueError):
            self.api().validate_pack(pack)

    def test_no_blocking_rule_can_be_enabled_by_data(self):
        pack = self.pack()
        pack["patterns"][0]["enforcement_enabled"] = True
        with self.assertRaises(ValueError):
            self.api().validate_pack(pack)

    def test_risk_and_safe_fixtures_are_required(self):
        pack = self.pack()
        pack["patterns"][0]["fixtures"] = []
        with self.assertRaises(ValueError):
            self.api().validate_pack(pack)

    def test_patch_and_cve_provenance_are_required(self):
        pack = self.pack()
        pack["patterns"][0]["evidence"] = []
        with self.assertRaises(ValueError):
            self.api().validate_pack(pack)

    def test_e5_query_and_passage_prefixes_are_not_interchangeable(self):
        api = self.api("embedding")
        self.assertEqual(api.prefixed(["path validation"], "query"), ["query: path validation"])
        self.assertEqual(api.prefixed(["path validation"], "passage"), ["passage: path validation"])
        with self.assertRaises(ValueError):
            api.prefixed([""], "query")

    def test_pooling_excludes_padding_and_normalizes(self):
        api = self.api("embedding")
        hidden = np.array([[[3., 0.], [0., 4.], [100., 100.]]], dtype=np.float32)
        vector = api.pool_and_normalize(hidden, np.array([[1, 1, 0]]))
        np.testing.assert_allclose(vector, [[0.6, 0.8]], atol=1e-6)

    def test_missing_model_does_not_automatically_download(self):
        api = self.api("embedding")
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(FileNotFoundError):
                api.LocalEmbedder(Path(root))

    def test_artifact_hash_mismatch_is_rejected(self):
        api = self.api("embedding")
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "model.onnx"
            path.write_bytes(b"untrusted weights")
            with self.assertRaisesRegex(ValueError, "hash"):
                api.verify_artifacts(Path(root), {"files": [{"name": "model.onnx", "sha256": "0" * 64}]} )

    def test_index_identity_changes_with_pack_and_model(self):
        api = self.api()
        first = api.index_identity("workspace", "a" * 64, "b" * 64)
        self.assertNotEqual(first, api.index_identity("workspace", "c" * 64, "b" * 64))
        self.assertNotEqual(first, api.index_identity("workspace", "a" * 64, "d" * 64))

    def test_empty_query_and_invalid_limit_fail_before_model_or_db(self):
        api = self.api()
        for query, limit in [("", 5), ("path", 0), ("path", 100)]:
            result = api.search_patterns(ROOT, query, limit=limit)
            self.assertEqual(result["status"], "invalid_request")

    def test_unsupported_family_does_not_load_model(self):
        result = self.api().search_patterns(ROOT, "anything", family="unknown")
        self.assertEqual(result["status"], "unsupported")

    def test_index_without_prepared_model_is_unavailable(self):
        from paladin.local import setup
        api = self.api()
        with tempfile.TemporaryDirectory() as root:
            setup(Path(root), start=False)
            result = api.build_index(Path(root))
            self.assertEqual(result["status"], "unavailable")
            self.assertFalse((Path(root) / ".paladin/semantic-index.json").exists())

    def test_search_without_index_is_not_no_known_match(self):
        api = self.api()
        with tempfile.TemporaryDirectory() as root:
            result = api.search_patterns(Path(root), "download file")
            self.assertEqual(result["status"], "unavailable")
            self.assertNotIn("no_known_match", json.dumps(result))

    def test_cli_validates_pack_without_downloading_or_connecting(self):
        import contextlib, io
        from paladin.cli import main
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["patterns", "validate", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["pattern_count"], 30)

    def test_cli_search_reports_unavailable_index_as_json(self):
        import contextlib, io
        from paladin.cli import main
        with tempfile.TemporaryDirectory() as root:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["search", "upload path", "--workspace", root, "--json"])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(output.getvalue())["status"], "unavailable")

    def test_cli_semantic_doctor_separates_index_readiness(self):
        import contextlib, io
        from paladin.cli import main
        with tempfile.TemporaryDirectory() as root:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["doctor", "--semantic", "--workspace", root, "--json"])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(output.getvalue())["semantic"]["status"], "unavailable")

    def test_non_english_input_is_rejected_before_model_or_db(self):
        from unittest.mock import patch
        api = self.api()
        for query in ["\uacbd\ub85c", "path \ud655\uc778", "caf\u00e9", "path\x00name"]:
            with self.subTest(query=ascii(query)), patch.object(api, "load_pack", side_effect=AssertionError("must not load")):
                result = api.search_patterns(ROOT, query)
                self.assertEqual(result["status"], "invalid_request")
                self.assertIn("English", result["error"])
            with self.assertRaisesRegex(ValueError, "English"):
                self.api("embedding").prefixed([query], "passage")

    def test_pack_rejects_non_english_authored_text(self):
        pack = self.pack()
        pack["patterns"][0]["title"] = "\uc81c\ubaa9"
        with self.assertRaisesRegex(ValueError, "English"):
            self.api().validate_pack(pack)

    def test_technical_english_accepts_code_punctuation_and_whitespace(self):
        text = "Validate safe_join(path, root)\nwith shell=False; CVE-2024-49766."
        self.assertEqual(self.api("embedding").prefixed([text], "query"), ["query: " + text])

    def test_cli_rejects_non_english_as_json(self):
        import contextlib, io
        from paladin.cli import main
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["search", "\uc5c5\ub85c\ub4dc", "--json"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue())["status"], "invalid_request")

    def test_current_evaluation_supports_only_english(self):
        from paladin.language import require_english
        fixture = json.loads((ROOT / "eval/m2-queries.json").read_text(encoding="utf-8"))
        self.assertEqual(len(fixture["queries"]), 20)
        for item in fixture["queries"]:
            self.assertEqual(item["language"], "en")
            require_english(item["query"])

    def test_input_policy_change_invalidates_encoder_identity(self):
        from unittest.mock import patch
        api = self.api()
        previous = api.encoder_identity()
        with patch.object(api, "TEXT_POLICY", "different-policy"):
            self.assertNotEqual(previous, api.encoder_identity())

    def test_diagnostic_embedding_also_rejects_unsupported_text(self):
        from paladin.local import diagnostic_embedding
        with self.assertRaisesRegex(ValueError, "English"):
            diagnostic_embedding("\ud55c\uae00")

    def test_stale_index_cannot_be_used_with_current_pack(self):
        from paladin.local import setup
        api = self.api()
        with tempfile.TemporaryDirectory() as root:
            setup(Path(root), start=False)
            (Path(root) / ".paladin/semantic-index.json").write_text('{"pack_sha256": "old"}')
            result = api.search_patterns(Path(root), "download files")
            self.assertEqual(result["status"], "unavailable")
            self.assertIn("stale", result["error"])


if __name__ == "__main__":
    unittest.main()
