"""Pinned ONNX E5 encoder. Only prepare_model downloads; inference is local."""
import hashlib
from importlib import resources
import json
from pathlib import Path
import sys
import time
import urllib.request
import uuid

import numpy as np

from paladin.local import _state
from paladin.language import require_english


def model_lock():
    return json.loads(resources.files("paladin").joinpath("resources/embedding-model.json").read_text(encoding="utf-8"))


def digest_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def model_directory(root):
    state = _state(root)
    path = state / "models" / model_lock()["revision"]
    if not path.resolve().is_relative_to(state.resolve()):
        raise ValueError("model path escapes workspace")
    return path


def verify_artifacts(directory, lock):
    directory = Path(directory).resolve()
    for entry in lock["files"]:
        path = directory / entry["name"]
        if Path(entry["name"]).name != entry["name"] or not path.resolve().is_relative_to(directory):
            raise ValueError("invalid model artifact path")
        if not path.is_file():
            raise FileNotFoundError("model is not prepared; run paladin model prepare")
        if digest_file(path) != entry["sha256"]:
            raise ValueError("model artifact hash mismatch: " + entry["name"])


def prepare_model(root):
    """Explicit, hash-checked artifact acquisition from one pinned repository."""
    lock = model_lock()
    directory = model_directory(root)
    directory.mkdir(parents=True, exist_ok=True)
    for entry in lock["files"]:
        target = directory / entry["name"]
        if target.exists():
            verify_artifacts(directory, {"files": [entry]})
            continue
        temp = directory / (entry["name"] + "." + uuid.uuid4().hex + ".part")
        url = f"https://huggingface.co/{lock['model_id']}/resolve/{lock['revision']}/{entry['source']}"
        print("Downloading pinned model artifact: " + entry["name"], file=sys.stderr, flush=True)
        started = time.monotonic()
        total = 0
        try:
            with urllib.request.urlopen(url, timeout=30) as response, temp.open("xb") as stream:
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > entry["size"] or time.monotonic() - started > 900:
                        raise ValueError("model artifact exceeds download limits")
                    stream.write(chunk)
            if total != entry["size"] or digest_file(temp) != entry["sha256"]:
                raise ValueError("downloaded model artifact size/hash mismatch")
            temp.replace(target)
        finally:
            if temp.exists():
                temp.unlink()
    verify_artifacts(directory, lock)
    return {"status": "prepared", "model_id": lock["model_id"], "revision": lock["revision"],
            "dimension": lock["dimension"], "directory": str(directory), "inference": "local_cpu"}


def prefixed(texts, kind):
    if kind not in {"query", "passage"} or not texts:
        raise ValueError("embedding kind must be query or passage with nonempty texts")
    if any(not isinstance(t, str) or not t.strip() or len(t.encode("utf-8")) > 20000 for t in texts):
        raise ValueError("embedding text must be nonempty and at most 20000 bytes")
    for text in texts:
        require_english(text)
    return [kind + ": " + t.strip() for t in texts]


def pool_and_normalize(hidden, mask):
    if hidden.ndim != 3 or hidden.shape[:2] != mask.shape or not np.all(mask.sum(axis=1) > 0):
        raise ValueError("invalid embedding tensors")
    pooled = (hidden * mask[..., None]).sum(axis=1) / mask.sum(axis=1)[:, None]
    norms = np.linalg.norm(pooled, axis=1, keepdims=True)
    if not np.all(np.isfinite(pooled)) or np.any(norms == 0):
        raise ValueError("invalid embedding values")
    return (pooled / norms).astype(np.float32)


class LocalEmbedder:
    def __init__(self, root):
        lock = model_lock()
        directory = model_directory(root)
        verify_artifacts(directory, lock)
        # No transformer auto-loader or repository Python code is evaluated.
        from tokenizers import Tokenizer
        import onnxruntime as ort
        ort.disable_telemetry_events()
        self.tokenizer = Tokenizer.from_file(str(directory / "tokenizer.json"))
        self.tokenizer.no_truncation()
        self.tokenizer.enable_padding(pad_id=1, pad_token="<pad>")
        options = ort.SessionOptions()
        options.intra_op_num_threads = 4
        options.inter_op_num_threads = 1
        self.session = ort.InferenceSession(str(directory / "model.onnx"), sess_options=options,
                                            providers=["CPUExecutionProvider"])
        self.inputs = {item.name for item in self.session.get_inputs()}
        self.lock = lock

    def encode(self, texts, kind):
        texts = prefixed(texts, kind)
        vectors = []
        for offset in range(0, len(texts), 4):
            encoded = self.tokenizer.encode_batch(texts[offset:offset + 4])
            if any(len(item.ids) > self.lock["max_tokens"] for item in encoded):
                raise ValueError("text exceeds 512 tokens; split the passage instead of silently truncating")
            mask = np.array([item.attention_mask for item in encoded], dtype=np.int64)
            arrays = {"input_ids": np.array([item.ids for item in encoded], dtype=np.int64), "attention_mask": mask,
                      "token_type_ids": np.array([item.type_ids for item in encoded], dtype=np.int64)}
            hidden = self.session.run(None, {k: arrays[k] for k in self.inputs})[0]
            batch = pool_and_normalize(hidden, mask)
            if batch.shape[1] != self.lock["dimension"]:
                raise ValueError("model output dimension mismatch")
            vectors.extend(batch.tolist())
        return vectors
