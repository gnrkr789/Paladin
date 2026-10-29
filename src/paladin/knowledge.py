"""Source-qualified advisory retrieval. Similarity is not a vulnerability verdict."""
from contextlib import closing
import base64
import hashlib
from importlib import metadata, resources
import json
from pathlib import Path
import sqlite3

from jsonschema import Draft202012Validator, FormatChecker
import numpy as np

from paladin.embedding import LocalEmbedder, model_lock, model_directory, verify_artifacts
from paladin.local import _state, _read_config, _verify_metadata
from paladin.language import TEXT_POLICY, require_english, validate_authored_text

FAMILIES = {"path_traversal", "sql_injection", "ssrf", "command_injection", "unsafe_deserialization"}


def _resource(name):
    return resources.files("paladin").joinpath("resources/" + name).read_bytes()


def validate_pack(pack):
    validate_authored_text(pack)
    schema = json.loads(_resource("prevention-pack.schema.json"))
    errors = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(pack))
    if errors:
        raise ValueError("invalid prevention pack: " + errors[0].message[:400])
    ids = [p["pattern_id"] for p in pack["patterns"]]
    cves = [p["cve_id"] for p in pack["patterns"]]
    if len(ids) != len(set(ids)) or len(cves) != len(set(cves)):
        raise ValueError("duplicate pattern or CVE")
    if {p["family"] for p in pack["patterns"]} != FAMILIES:
        raise ValueError("pack must cover the five selected families")
    for pattern in pack["patterns"]:
        if pattern["pattern_id"] != pattern["cve_id"]:
            raise ValueError("pattern/CVE identity mismatch")
    return pack


def load_pack():
    raw = _resource("prevention-pack.json")
    lock = json.loads(_resource("prevention-pack.lock.json"))
    if hashlib.sha256(raw).hexdigest() != lock["sha256"]:
        raise ValueError("bundled prevention pack hash mismatch")
    pack = validate_pack(json.loads(raw))
    if len(pack["patterns"]) != lock["pattern_count"] or pack["pack_id"] != lock["pack_id"]:
        raise ValueError("bundled prevention pack manifest mismatch")
    return pack


def encoder_identity():
    spec = {"model": model_lock(), "text_format_version": "prevention-card-v1", "text_policy": TEXT_POLICY,
            "runtime_versions": {name: metadata.version(name) for name in ["onnxruntime", "tokenizers", "numpy"]}}
    return hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()


def index_identity(workspace, pack_sha, model_sha):
    return "paladin_patterns_" + hashlib.sha256((str(workspace) + pack_sha + model_sha).encode()).hexdigest()[:24]


def _manifest(root, pack):
    pack_sha = hashlib.sha256(_resource("prevention-pack.json")).hexdigest()
    model_sha = encoder_identity()
    return {"schema_version": "1", "pack_id": pack["pack_id"], "pack_sha256": pack_sha,
            "encoder_sha256": model_sha, "model_id": model_lock()["model_id"],
            "model_revision": model_lock()["revision"], "dimension": 384,
            "pattern_count": len(pack["patterns"]),
            "collection": index_identity(Path(root).resolve(), pack_sha, model_sha)}


def passage(pattern):
    return (pattern["title"] + "\nCause: " + pattern["cause"] + "\nConditions: "
            + " ".join(pattern["preconditions"]) + "\nPrevention: " + pattern["prevention"]
            + "\nLimits: " + pattern["limitations"])


def _context(root):
    state = _state(root)
    config = _read_config(state)
    _verify_metadata(root, state)
    path = state / "semantic-index.json"
    if not path.resolve().is_relative_to(state.resolve()) or path.is_symlink():
        raise ValueError("semantic manifest path escapes workspace")
    return state, config


def _active_manifest(root, pack):
    state, config = _context(root)
    expected = _manifest(root, pack)
    manifest = json.loads((state / "semantic-index.json").read_text(encoding="utf-8"))
    if manifest != expected:
        raise ValueError("semantic index is stale; reindex the current pack/model/runtime")
    with closing(sqlite3.connect((state / "metadata.sqlite3").resolve().as_uri() + "?mode=ro", uri=True)) as db:
        row = db.execute("SELECT manifest FROM semantic_index WHERE id = 'active'").fetchone()
    if row is None or json.loads(row[0]) != expected:
        raise ValueError("semantic index SQLite manifest mismatch")
    return state, config, manifest


SNAPSHOT = "prevention-vectors.json"


def _snapshot_identity(pack):
    return {"pack_id": pack["pack_id"], "pack_sha256": hashlib.sha256(_resource("prevention-pack.json")).hexdigest(),
            "encoder_sha256": encoder_identity(), "model_id": model_lock()["model_id"],
            "model_revision": model_lock()["revision"], "dimension": 384}


def snapshot_vectors(pack):
    """Packaged passage vectors for this exact pack and encoder, or None if they do not apply."""
    try:
        snapshot = json.loads(_resource(SNAPSHOT))
    except (OSError, FileNotFoundError, ValueError):
        return None
    if not isinstance(snapshot, dict) or snapshot.get("identity") != _snapshot_identity(pack):
        return None
    vectors = []
    for pattern in pack["patterns"]:
        encoded = snapshot.get("vectors", {}).get(pattern["pattern_id"])
        if not isinstance(encoded, str):
            return None
        array = np.frombuffer(base64.b64decode(encoded, validate=True), dtype="<f4")
        if array.shape != (384,) or not np.all(np.isfinite(array)):
            return None
        vectors.append(array.astype(np.float32).tolist())
    return vectors


def export_snapshot(root):
    """Compute passage vectors with the local model and write the packaged snapshot."""
    pack = load_pack()
    vectors = LocalEmbedder(root).encode([passage(p) for p in pack["patterns"]], "passage")
    array = np.asarray(vectors, dtype="<f4")
    if array.shape != (len(pack["patterns"]), 384) or not np.all(np.isfinite(array)):
        raise ValueError("invalid semantic embedding matrix")
    snapshot = {"schema_version": 1, "identity": _snapshot_identity(pack),
                "note": "Passage vectors of prevention-pack.json; queries still need the local model.",
                "vectors": {p["pattern_id"]: base64.b64encode(row.tobytes()).decode("ascii")
                            for p, row in zip(pack["patterns"], array)}}
    path = Path(__file__).parent / "resources" / SNAPSHOT
    path.write_bytes((json.dumps(snapshot, indent=1, sort_keys=True) + "\n").encode("ascii"))
    return {"status": "exported", "path": str(path), "pattern_count": len(pack["patterns"]),
            "identity": snapshot["identity"]}


def build_index(root):
    try:
        state, config = _context(root)
        pack = load_pack()
        manifest = _manifest(root, pack)
        # Packaged vectors make every install index the same bytes without loading the model.
        vectors = snapshot_vectors(pack)
        source = "snapshot"
        if vectors is None:
            vectors = LocalEmbedder(root).encode([passage(p) for p in pack["patterns"]], "passage")
            source = "computed"
        store = SemanticStore(config)
        try:
            store.write(manifest, pack["patterns"], vectors)
        finally:
            store.close()
        encoded = json.dumps(manifest, sort_keys=True)
        with closing(sqlite3.connect(state / "metadata.sqlite3")) as db, db:
            db.execute("CREATE TABLE IF NOT EXISTS semantic_index (id TEXT PRIMARY KEY, manifest TEXT NOT NULL)")
            db.execute("INSERT OR REPLACE INTO semantic_index VALUES ('active', ?)", (encoded,))
        temp = state / "semantic-index.json.tmp"
        if temp.is_symlink() or not temp.resolve().is_relative_to(state.resolve()):
            raise ValueError("unsafe semantic manifest temporary path")
        temp.write_text(encoded + "\n", encoding="utf-8")
        temp.replace(state / "semantic-index.json")
        return {"status": "indexed", "manifest": manifest, "vector_source": source,
                "security_ready": False, "enforcement_enabled": False}
    except Exception as exc:
        return _failure(exc)


def _failure(exc):
    return {"status": "unavailable", "security_ready": False, "error": f"{type(exc).__name__}: {str(exc)[:600]}"}


def knowledge_status(root):
    try:
        pack = load_pack()
        state, config, manifest = _active_manifest(root, pack)
        verify_artifacts(model_directory(root), model_lock())
        store = SemanticStore(config)
        try:
            if not store.matches(manifest):
                raise ValueError("Milvus semantic schema or record manifest mismatch")
        finally:
            store.close()
        return {"status": "ready", "manifest": manifest, "verification_status": "source_observed",
                "security_ready": False, "enforcement_enabled": False}
    except Exception as exc:
        return _failure(exc)


def search_patterns(root, query, *, limit=5, family=None, embedder=None):
    if (not isinstance(query, str) or not query.strip() or len(query.encode("utf-8")) > 20000
            or isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 20):
        return {"status": "invalid_request", "security_ready": False, "error": "nonempty query and limit 1..20 required"}
    try:
        require_english(query)
    except ValueError as exc:
        return {"status": "invalid_request", "security_ready": False, "error": str(exc)}
    if family is not None and family not in FAMILIES:
        return {"status": "unsupported", "security_ready": False, "error": "unsupported pattern family"}
    try:
        pack = load_pack()
        state, config, manifest = _active_manifest(root, pack)
        vector = (embedder or LocalEmbedder(root)).encode([query], "query")[0]
        store = SemanticStore(config)
        try:
            if not store.matches(manifest):
                raise ValueError("Milvus semantic index manifest mismatch")
            hits = store.search(manifest, vector, limit, family)
        finally:
            store.close()
        patterns = {p["pattern_id"]: p for p in pack["patterns"]}
        matches = []
        for hit in hits:
            if hit["id"] not in patterns:
                raise ValueError("index contains unknown pattern identity")
            matches.append({"pattern": patterns[hit["id"]], "cosine_similarity": hit["distance"],
                            "applicability": "must_verify_preconditions"})
        return {"status": "complete", "judgment": "reference_candidates" if matches else "no_known_match",
                "matches": matches, "manifest": manifest, "security_ready": False,
                "notice": "Advisory references only. Similarity is not a vulnerability probability or blocking verdict."}
    except Exception as exc:
        return _failure(exc)


class SemanticStore:
    def __init__(self, config):
        from pymilvus import MilvusClient
        self.timeout = config["milvus"]["timeout_seconds"]
        self.client = MilvusClient(uri=config["milvus"]["uri"], timeout=self.timeout)

    def _schema_matches(self, manifest):
        from pymilvus import DataType
        name = manifest["collection"]
        if not self.client.has_collection(name, timeout=self.timeout):
            return False
        schema = self.client.describe_collection(name, timeout=self.timeout)
        fields = {f["name"]: f for f in schema["fields"]}
        expected = {"id": DataType.VARCHAR, "vector": DataType.FLOAT_VECTOR,
                    "family": DataType.VARCHAR, "pack_sha": DataType.VARCHAR, "model_sha": DataType.VARCHAR}
        return (set(fields) == set(expected) and all(fields[k]["type"] == v for k, v in expected.items())
                and fields["id"].get("is_primary", False) and not schema.get("auto_id", False)
                and not schema.get("enable_dynamic_field", False)
                and int(fields["vector"].get("params", {}).get("dim", 0)) == manifest["dimension"])

    def matches(self, manifest):
        if not self._schema_matches(manifest):
            return False
        rows = self.client.query(manifest["collection"], filter="", output_fields=["id", "pack_sha", "model_sha"],
                                 limit=1000, consistency_level="Strong", timeout=self.timeout)
        expected_ids = {p["pattern_id"] for p in load_pack()["patterns"]}
        return (len(rows) == manifest["pattern_count"] and {r["id"] for r in rows} == expected_ids
                and all(r["pack_sha"] == manifest["pack_sha256"] and r["model_sha"] == manifest["encoder_sha256"] for r in rows))

    def write(self, manifest, patterns, vectors):
        from pymilvus import DataType
        array = np.asarray(vectors, dtype=np.float32)
        if array.shape != (len(patterns), manifest["dimension"]) or not np.all(np.isfinite(array)):
            raise ValueError("invalid semantic embedding matrix")
        name = manifest["collection"]
        if not self.client.has_collection(name, timeout=self.timeout):
            schema = self.client.create_schema(auto_id=False, enable_dynamic_field=False)
            schema.add_field("id", DataType.VARCHAR, is_primary=True, max_length=64)
            schema.add_field("vector", DataType.FLOAT_VECTOR, dim=manifest["dimension"])
            for field in ["family", "pack_sha", "model_sha"]:
                schema.add_field(field, DataType.VARCHAR, max_length=64)
            indexes = self.client.prepare_index_params()
            indexes.add_index(field_name="vector", index_type="FLAT", metric_type="COSINE")
            self.client.create_collection(name, schema=schema, index_params=indexes, timeout=30)
        if not self._schema_matches(manifest):
            raise ValueError("existing semantic collection schema mismatch; preserved")
        rows = [{"id": p["pattern_id"], "vector": v, "family": p["family"],
                 "pack_sha": manifest["pack_sha256"], "model_sha": manifest["encoder_sha256"]}
                for p, v in zip(patterns, vectors)]
        self.client.upsert(name, rows, timeout=30)
        self.client.flush(name, timeout=30)
        self.client.load_collection(name, timeout=30)
        if not self.matches(manifest):
            raise ValueError("semantic index readback failed")

    def search(self, manifest, vector, limit, family):
        expression = "" if family is None else 'family == "' + family + '"'
        return self.client.search(manifest["collection"], data=[vector], anns_field="vector", limit=limit,
                                  filter=expression, consistency_level="Strong", timeout=self.timeout)[0]

    def close(self):
        self.client.close()
