"""Hybrid retrieval: BM25 over pack passages fused with dense ranks (reciprocal rank fusion)."""
import unittest

from paladin import lexical

PATTERNS = [
    {"pattern_id": "CVE-2000-0001", "text": "Shell command built from a run identifier in workflow tasks"},
    {"pattern_id": "CVE-2000-0002", "text": "Command injection through a terminal title helper"},
    {"pattern_id": "CVE-2000-0003", "text": "Open redirect after login through a next parameter"},
]


class LexicalTests(unittest.TestCase):
    def setUp(self):
        self.index = lexical.Bm25({p["pattern_id"]: p["text"] for p in PATTERNS})

    def test_rare_query_terms_score_the_documents_that_contain_them(self):
        scores = self.index.scores("Which run identifier reaches the shell in my workflow?")

        self.assertEqual(max(scores, key=scores.get), "CVE-2000-0001")
        self.assertEqual(scores["CVE-2000-0003"], 0)

    def test_fusion_lifts_lexical_matches_over_a_dense_hit_without_term_support(self):
        dense = ["CVE-2000-0003", "CVE-2000-0001", "CVE-2000-0002"]

        fused = lexical.fuse(dense, self.index.scores("run identifier in a workflow shell command"), limit=2)

        self.assertEqual(fused, ["CVE-2000-0001", "CVE-2000-0002"])

    def test_fusion_keeps_dense_order_when_no_query_term_matches(self):
        dense = ["CVE-2000-0003", "CVE-2000-0002", "CVE-2000-0001"]

        self.assertEqual(lexical.fuse(dense, self.index.scores("zzz qqq"), limit=3), dense)

    def test_fusion_only_returns_dense_candidates(self):
        fused = lexical.fuse(["CVE-2000-0003"], self.index.scores("run identifier workflow"), limit=5)

        self.assertEqual(fused, ["CVE-2000-0003"])


class HybridSearchTests(unittest.TestCase):
    def test_search_reorders_a_wide_dense_pool_and_returns_the_limit(self):
        from unittest.mock import patch
        from paladin import knowledge
        pack = knowledge.load_pack()
        target = next(p for p in pack["patterns"] if p["pattern_id"] == "CVE-2024-22195")
        self.assertIn("xmlattr", knowledge.passage(target).lower(), "test relies on the card naming the filter")
        others = [p["pattern_id"] for p in pack["patterns"] if p is not target][:7]
        requested = {}

        class Store:
            def __init__(self, config):
                pass

            def matches(self, manifest):
                return True

            def search(self, manifest, vector, limit, family):
                requested["limit"] = limit
                return [{"id": key, "distance": 0.9 - i / 100} for i, key in enumerate(others + [target["pattern_id"]])]

            def close(self):
                pass

        class Embedder:
            def encode(self, texts, kind):
                return [[0.0]]

        with patch("paladin.knowledge._active_manifest", return_value=(None, {}, {})), \
                patch("paladin.knowledge.SemanticStore", Store):
            result = knowledge.search_patterns(".", "Can user keys passed to the xmlattr filter inject attributes?",
                                               limit=3, embedder=Embedder())

        self.assertEqual(result["status"], "complete", result)
        self.assertEqual(requested["limit"], knowledge.DENSE_POOL)
        self.assertEqual(len(result["matches"]), 3)
        self.assertEqual(result["matches"][0]["pattern"]["pattern_id"], target["pattern_id"])
        self.assertAlmostEqual(result["matches"][0]["cosine_similarity"], 0.83)
        self.assertEqual(result["ranking"], "hybrid_bm25_rrf_v1")


if __name__ == "__main__":
    unittest.main()
