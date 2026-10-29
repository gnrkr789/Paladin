"""M1 local setup and read-only diagnostics. No vulnerability rules are enabled."""
import hashlib
from contextlib import closing
from importlib import metadata, resources
import json
import math
from pathlib import Path
import re
import sqlite3
import subprocess
import tomllib
from urllib.parse import urlsplit
from paladin.language import require_english

MILVUS_VERSION = "2.6.25"
SDK_VERSION = "2.6.17"
EMBEDDING_ID = "diagnostic-token-hash-v1"
DIMENSION = 64
CORPUS_ID = "m1-diagnostic-v1"
SAMPLES = [
    ("m1_path", "path traversal upload filename storage directory boundary"),
    ("m1_sql", "sql injection query parameter database ordering expression"),
    ("m1_command", "command process checkout argument option delimiter"),
]


def diagnostic_embedding(text):
    """Local token hashing for persistence/search plumbing, not semantic retrieval."""
    require_english(text)
    vector = [0.0] * DIMENSION
    for token in re.findall(r"\w+", text.lower()):
        index = int.from_bytes(hashlib.sha256(token.encode()).digest()[:4], "big") % DIMENSION
        vector[index] += 1.0
    norm = math.sqrt(sum(x * x for x in vector))
    if not norm:
        raise ValueError("diagnostic embedding requires nonempty tokens")
    return [x / norm for x in vector]


def _template():
    return resources.files("paladin").joinpath("resources/compose.yaml").read_bytes()


def _state(root):
    root = Path(root).resolve()
    state = root / ".paladin"
    if state.is_symlink() or not state.resolve().is_relative_to(root):
        raise ValueError("state directory must stay inside workspace")
    if state.exists():
        for name in ["config.toml", "compose.yaml", "manifest.json", "metadata.sqlite3", "data", "data/etcd", "data/minio", "data/milvus"]:
            path = state / name
            if path.is_symlink() or not path.resolve().is_relative_to(state.resolve()):
                raise ValueError(f"state path must stay inside workspace: {name}")
    return state


def _expected(root):
    suffix = hashlib.sha256(str(Path(root).resolve()).encode()).hexdigest()[:12]
    return {"schema_version": "1", "embedding_id": EMBEDDING_ID, "dimension": DIMENSION,
            "corpus_snapshot": CORPUS_ID, "collection": f"paladin_m1_{suffix}",
            "compose_project": f"paladin-{suffix}", "milvus_version": MILVUS_VERSION}


def _read_config(state):
    with (state / "config.toml").open("rb") as stream:
        config = tomllib.load(stream)
    if any(not isinstance(config.get(key), dict) for key in ["milvus", "embedding", "corpus"]):
        raise ValueError("milvus, embedding and corpus must be configuration tables")
    if not isinstance(config["milvus"].get("uri"), str):
        raise ValueError("milvus.uri must be a loopback URL string")
    uri = urlsplit(config["milvus"]["uri"])
    if (uri.scheme != "http" or uri.hostname != "127.0.0.1" or uri.port != 19530
            or uri.username or uri.password or uri.path not in {"", "/"} or uri.query or uri.fragment):
        raise ValueError("M1 requires loopback endpoint http://127.0.0.1:19530")
    if config["embedding"] != {"id": EMBEDDING_ID, "dimension": DIMENSION}:
        raise ValueError("embedding identity/dimension mismatch")
    if config["corpus"]["snapshot"] != CORPUS_ID:
        raise ValueError("diagnostic corpus snapshot mismatch")
    timeout = config["milvus"]["timeout_seconds"]
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
        raise ValueError("timeout_seconds must be in (0, 30]")
    return config


def _verify_metadata(root, state):
    expected = _expected(root)
    manifest = json.loads((state / "manifest.json").read_text(encoding="utf-8"))
    if manifest != expected:
        raise ValueError("local manifest identity mismatch")
    uri = (state / "metadata.sqlite3").resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        stored = dict(connection.execute("SELECT key, value FROM manifest"))
    if stored != {k: json.dumps(v) for k, v in expected.items()}:
        raise ValueError("SQLite manifest identity mismatch")
    return expected


def _write_once(path, content):
    try:
        with path.open("xb") as stream:
            stream.write(content)
    except FileExistsError:
        pass


def _prepare(root):
    state = _state(root)
    state.mkdir(parents=True, exist_ok=True)
    template = _template()
    compose = state / "compose.yaml"
    if compose.exists() and compose.read_bytes() != template:
        raise ValueError("compose_conflict: generated compose differs; existing file preserved")
    _write_once(compose, template)
    manifest = _expected(root)
    config = (f'[milvus]\nuri = "http://127.0.0.1:19530"\ntimeout_seconds = 5\n\n'
              f'[embedding]\nid = "{EMBEDDING_ID}"\ndimension = {DIMENSION}\n\n'
              f'[corpus]\nsnapshot = "{CORPUS_ID}"\n')
    _write_once(state / "config.toml", config.encode())
    _write_once(state / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())
    db = state / "metadata.sqlite3"
    if not db.exists():
        with closing(sqlite3.connect(db)) as connection, connection:
            connection.execute("CREATE TABLE manifest (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            connection.executemany("INSERT INTO manifest VALUES (?, ?)", [(k, json.dumps(v)) for k, v in manifest.items()])
    (state / "data").mkdir(exist_ok=True)
    config = _read_config(state)
    _verify_metadata(root, state)
    return state, config, manifest


def setup(root, *, start=True, runner=subprocess.run, store_factory=None):
    """Configure once, optionally start only this Compose project, and seed probes."""
    try:
        state, config, manifest = _prepare(root)
        if not start:
            return {"status": "configured", "security_ready": False,
                    "state_dir": str(state), "compose_project": manifest["compose_project"]}
        command = ["docker", "compose", "--project-name", manifest["compose_project"],
                   "--file", str(state / "compose.yaml"), "up", "-d", "--wait", "--wait-timeout", "240"]
        runner(command, check=True, capture_output=True, text=True, timeout=600)
        config["manifest"] = manifest
        store = (store_factory or MilvusStore)(config)
        try:
            store.initialize()
        finally:
            store.close()
        return doctor(root, store_factory=store_factory)
    except (OSError, ValueError, KeyError, sqlite3.Error, subprocess.SubprocessError) as exc:
        return {"status": "error", "security_ready": False, "error": _error(exc)}
    except Exception as exc:
        # SDK exceptions have multiple classes; preserve a bounded useful error
        # in the command contract rather than treating a failed setup as ready.
        return {"status": "error", "security_ready": False, "error": _error(exc)}


def _error(exc):
    if isinstance(exc, subprocess.CalledProcessError):
        return f"docker_compose_failed: {str(exc.stderr or exc)[:800]}"
    return f"{type(exc).__name__}: {str(exc)[:800]}"


def doctor(root, *, store_factory=None):
    """Read local state and query existing collections. Never creates/seeds them."""
    result = {"status": "unavailable", "security_ready": False, "checks": {}}
    checks = result["checks"]
    try:
        state = _state(root)
        config = _read_config(state)
        if (state / "compose.yaml").read_bytes() != _template():
            raise ValueError("compose_conflict: unexpected generated compose")
        checks["configuration"] = {"status": "ok", "uri": config["milvus"]["uri"]}
    except (OSError, ValueError, KeyError) as exc:
        checks["configuration"] = {"status": "error", "detail": _error(exc)}
        return result
    try:
        manifest = _verify_metadata(root, state)
        checks["local_metadata"] = {"status": "ok", **manifest}
    except (OSError, ValueError, KeyError, sqlite3.Error) as exc:
        checks["local_metadata"] = {"status": "error", "detail": _error(exc)}
        return result
    checks["embedding"] = {"status": "ok", "mode": "diagnostic_only", "id": EMBEDDING_ID, "dimension": DIMENSION}
    config["manifest"] = manifest
    try:
        store = (store_factory or MilvusStore)(config)
        try:
            inspected = store.inspect()
        finally:
            store.close()
    except Exception as exc:
        checks["milvus"] = {"status": "error", "detail": _error(exc)}
        return result
    checks["milvus"] = {"status": "ok" if inspected["server_version"].lstrip("v") == MILVUS_VERSION else "error",
                        "actual_version": inspected["server_version"], "expected_version": MILVUS_VERSION}
    for name, key in [("schema", "schema_matches"), ("corpus", "sample_matches"), ("search", "search_matches")]:
        checks[name] = {"status": "ok" if inspected[key] else "error"}
    checks["corpus"]["snapshot"] = CORPUS_ID
    checks["corpus"]["kind"] = "synthetic_diagnostic"
    result["status"] = "ready" if all(x["status"] == "ok" for x in checks.values()) else "degraded"
    return result


class MilvusStore:
    """SDK boundary. Collection identity is workspace scoped, never arbitrary."""
    def __init__(self, config):
        from pymilvus import MilvusClient
        if metadata.version("pymilvus") != SDK_VERSION:
            raise ValueError(f"PyMilvus {SDK_VERSION} required")
        self.timeout = config["milvus"]["timeout_seconds"]
        self.collection = config["manifest"]["collection"]
        self.client = MilvusClient(uri=config["milvus"]["uri"], timeout=self.timeout)

    def _schema_matches(self):
        from pymilvus import DataType
        info = self.client.describe_collection(self.collection, timeout=self.timeout)
        fields = {f["name"]: f for f in info["fields"]}
        expected = {"id": DataType.VARCHAR, "vector": DataType.FLOAT_VECTOR,
                    "text": DataType.VARCHAR, "embedding_id": DataType.VARCHAR}
        if set(fields) != set(expected) or any(fields[k]["type"] != v for k, v in expected.items()):
            return False
        return (fields["id"].get("is_primary", False) and not info.get("auto_id", False)
                and not info.get("enable_dynamic_field", False)
                and int(fields["vector"].get("params", {}).get("dim", 0)) == DIMENSION)

    def initialize(self):
        from pymilvus import DataType
        if not self.client.has_collection(self.collection, timeout=self.timeout):
            schema = self.client.create_schema(auto_id=False, enable_dynamic_field=False)
            schema.add_field("id", DataType.VARCHAR, is_primary=True, max_length=64)
            schema.add_field("vector", DataType.FLOAT_VECTOR, dim=DIMENSION)
            schema.add_field("text", DataType.VARCHAR, max_length=2048)
            schema.add_field("embedding_id", DataType.VARCHAR, max_length=128)
            indexes = self.client.prepare_index_params()
            indexes.add_index(field_name="vector", index_type="FLAT", metric_type="COSINE")
            self.client.create_collection(self.collection, schema=schema, index_params=indexes, timeout=30)
        if not self._schema_matches():
            raise ValueError("existing diagnostic collection has incompatible schema; preserved")
        rows = [{"id": key, "text": text, "vector": diagnostic_embedding(text), "embedding_id": EMBEDDING_ID}
                for key, text in SAMPLES]
        self.client.upsert(self.collection, rows, timeout=self.timeout)
        self.client.flush(self.collection, timeout=30)
        self.client.load_collection(self.collection, timeout=30)

    def inspect(self):
        version = self.client.get_server_version(timeout=self.timeout)
        result = {"server_version": version, "schema_matches": False, "sample_matches": False, "search_matches": False}
        if not self.client.has_collection(self.collection, timeout=self.timeout):
            return result
        result["schema_matches"] = bool(self._schema_matches())
        if not result["schema_matches"]:
            return result
        expected = {key: text for key, text in SAMPLES}
        rows = self.client.query(self.collection, filter='id in ["m1_path", "m1_sql", "m1_command"]',
                                 output_fields=["id", "text", "embedding_id"], consistency_level="Strong", timeout=self.timeout)
        result["sample_matches"] = (len(rows) == len(expected) and all(
            row["id"] in expected and row["text"] == expected[row["id"]] and row["embedding_id"] == EMBEDDING_ID for row in rows))
        hits = self.client.search(self.collection, data=[diagnostic_embedding(text) for _, text in SAMPLES],
                                  anns_field="vector", limit=1, output_fields=["text"],
                                  consistency_level="Strong", timeout=self.timeout)
        result["search_matches"] = (len(hits) == len(SAMPLES) and all(
            hit and hit[0]["id"] == sample[0] for hit, sample in zip(hits, SAMPLES)))
        return result

    def close(self):
        self.client.close()
