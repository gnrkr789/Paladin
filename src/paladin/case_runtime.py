"""Explicit local sandbox configuration bound to the packaged observer assets."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from paladin import sandbox_runtime
from paladin.language import require_english

MAX_STATE_BYTES = 4096
FIELDS = {"image_id", "observer_id", "build_context_sha256", "build_log_sha256"}
HASH = re.compile(r"[0-9a-f]{64}\Z")


def _regular(path, directory=False):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("runtime_linked_path")
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ValueError("runtime_path_not_regular")
    return info


def _state(workspace, create=False):
    workspace = Path(workspace).absolute()
    require_english(str(workspace))
    for parent in reversed((workspace, *workspace.parents)):
        _regular(parent, directory=True)
    state = workspace / ".paladin"
    if create:
        state.mkdir(exist_ok=True)
    _regular(state, directory=True)
    return state


def current_build_context_sha256():
    assets = sandbox_runtime.ASSETS
    _regular(assets, directory=True)
    payload = []
    for name in sandbox_runtime.ASSET_NAMES:
        path = assets / name
        _regular(path)
        payload.append(path.name.encode("ascii") + b"\0" + path.read_bytes())
    if not payload:
        raise ValueError("runtime_assets_missing")
    return hashlib.sha256(b"".join(payload)).hexdigest()


def _validate(identity):
    if not isinstance(identity, dict) or set(identity) != FIELDS:
        raise ValueError("runtime_invalid_identity")
    if any(not isinstance(value, str) for value in identity.values()):
        raise ValueError("runtime_invalid_identity")
    if not sandbox_runtime.IMAGE_PATTERN.fullmatch(identity["image_id"]):
        raise ValueError("runtime_requires_immutable_image_id")
    if identity["observer_id"] != sandbox_runtime.OBSERVER_ID:
        raise ValueError("runtime_observer_identity_changed")
    if any(not HASH.fullmatch(identity[key]) for key in ("build_context_sha256", "build_log_sha256")):
        raise ValueError("runtime_invalid_digest")
    if identity["build_context_sha256"] != current_build_context_sha256():
        raise ValueError("runtime_build_context_changed")
    return identity


def configure_runtime(workspace, evidence_dir=None):
    """Build only on explicit request, then persist the validated image identity."""
    state = _state(workspace, create=True)
    destination = state / "runtime.json"
    if destination.exists() or destination.is_symlink():
        _regular(destination)
    identity = _validate(sandbox_runtime.build_runtime(evidence_dir=evidence_dir))
    raw = (json.dumps(identity, sort_keys=True, indent=2) + "\n").encode("ascii")
    with tempfile.NamedTemporaryFile(dir=state, prefix="runtime-", suffix=".tmp", delete=False) as stream:
        pending = Path(stream.name)
        stream.write(raw)
    try:
        _regular(state, directory=True)
        if destination.exists() or destination.is_symlink():
            _regular(destination)
        os.replace(pending, destination)
    finally:
        pending.unlink(missing_ok=True)
    return identity


def _unique_object(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("runtime_invalid_json")
        output[key] = value
    return output


def load_runtime(workspace):
    """Load a bounded regular state file; never build or execute a target."""
    try:
        state = _state(workspace)
        path = state / "runtime.json"
        info = _regular(path)
    except FileNotFoundError as exc:
        raise ValueError("runtime_not_configured") from exc
    if info.st_size > MAX_STATE_BYTES:
        raise ValueError("runtime_state_too_large")
    with path.open("rb") as stream:
        raw = stream.read(MAX_STATE_BYTES + 1)
    if len(raw) > MAX_STATE_BYTES:
        raise ValueError("runtime_state_too_large")
    try:
        identity = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("runtime_invalid_json") from exc
    return _validate(identity)
