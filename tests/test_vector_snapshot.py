"""Packaged passage vectors: used only when pack and encoder identities match."""
import unittest
from unittest.mock import patch

import numpy as np

from paladin import knowledge


class VectorSnapshotTests(unittest.TestCase):
    def test_packaged_snapshot_covers_every_pattern_for_the_current_identity(self):
        pack = knowledge.load_pack()
        vectors = knowledge.snapshot_vectors(pack)
        self.assertIsNotNone(vectors)
        array = np.asarray(vectors, dtype=np.float32)
        self.assertEqual(array.shape, (len(pack["patterns"]), 384))
        self.assertTrue(np.all(np.isfinite(array)))
        self.assertTrue(np.allclose(np.linalg.norm(array, axis=1), 1.0, atol=1e-3))

    def test_snapshot_is_ignored_when_the_encoder_or_pack_changes(self):
        pack = knowledge.load_pack()
        with patch("paladin.knowledge.encoder_identity", return_value="0" * 64):
            self.assertIsNone(knowledge.snapshot_vectors(pack))
        changed = dict(pack, pack_id="other-pack")
        self.assertIsNone(knowledge.snapshot_vectors(changed))
        missing = dict(pack, patterns=pack["patterns"] + [dict(pack["patterns"][0], pattern_id="CVE-0000-0000")])
        self.assertIsNone(knowledge.snapshot_vectors(missing))

    def test_index_uses_the_snapshot_without_loading_the_model(self):
        import tempfile
        from pathlib import Path
        written = {}

        class Store:
            def __init__(self, config):
                pass

            def write(self, manifest, patterns, vectors):
                written["ids"] = [pattern["pattern_id"] for pattern in patterns]
                written["vectors"] = vectors

            def close(self):
                pass

        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            with patch("paladin.knowledge._context", return_value=(state, {})), \
                    patch("paladin.knowledge.SemanticStore", Store), \
                    patch("paladin.knowledge.LocalEmbedder", side_effect=AssertionError("model loaded")):
                result = knowledge.build_index(folder)
            self.assertEqual(result["status"], "indexed", result)
            self.assertEqual(result["vector_source"], "snapshot")
            self.assertTrue((state / "semantic-index.json").exists())
        pack = knowledge.load_pack()
        self.assertEqual(written["ids"], [pattern["pattern_id"] for pattern in pack["patterns"]])
        self.assertEqual(written["vectors"], knowledge.snapshot_vectors(pack))

    def test_index_computes_vectors_when_the_snapshot_does_not_apply(self):
        import tempfile
        from pathlib import Path

        class Store:
            def __init__(self, config):
                pass

            def write(self, manifest, patterns, vectors):
                pass

            def close(self):
                pass

        class Embedder:
            def __init__(self, root):
                pass

            def encode(self, texts, kind):
                return [[0.0] * 383 + [1.0] for _ in texts]

        with tempfile.TemporaryDirectory() as folder:
            with patch("paladin.knowledge._context", return_value=(Path(folder), {})), \
                    patch("paladin.knowledge.SemanticStore", Store), \
                    patch("paladin.knowledge.snapshot_vectors", return_value=None), \
                    patch("paladin.knowledge.LocalEmbedder", Embedder):
                result = knowledge.build_index(folder)
        self.assertEqual((result["status"], result["vector_source"]), ("indexed", "computed"))


if __name__ == "__main__":
    unittest.main()
