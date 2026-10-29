"""Host-side evidence authentication; keys never enter target execution."""
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat

from paladin.language import require_english, validate_authored_text

AUTH_KIND = "paladin-host-hmac-sha256-v1"


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":")).encode("ascii")


def _key(workspace, create):
    root = Path(workspace).absolute()
    require_english(str(root))
    state = root / ".paladin"
    if create and not state.exists():
        state.mkdir()
    for path in (root, state):
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & 0x400):
            raise ValueError("unsafe_case_key_directory")
    path = state / "case-auth.key"
    if create:
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(os.urandom(32))
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            pass
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400 or info.st_nlink != 1 or info.st_size != 32):
        raise ValueError("invalid_case_key")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("case_key_changed")
        key = stream.read(33)
    if len(key) != 32:
        raise ValueError("invalid_case_key")
    return key


def sign_evidence(workspace, evidence):
    if not isinstance(evidence, dict) or "auth" in evidence:
        raise ValueError("unsigned_evidence_required")
    validate_authored_text(evidence)
    result = copy.deepcopy(evidence)
    key = _key(workspace, create=True)
    result["auth"] = {"kind": AUTH_KIND, "key_id": hashlib.sha256(key).hexdigest(),
                      "signature": hmac.new(key, _canonical(result), hashlib.sha256).hexdigest()}
    return result


def verify_evidence(workspace, evidence):
    try:
        if not isinstance(evidence, dict):
            return False
        auth = evidence.get("auth")
        if not isinstance(auth, dict) or set(auth) != {"kind", "key_id", "signature"} or auth["kind"] != AUTH_KIND:
            return False
        key = _key(workspace, create=False)
        content = {name: value for name, value in evidence.items() if name != "auth"}
        expected = hmac.new(key, _canonical(content), hashlib.sha256).hexdigest()
        return (isinstance(auth["signature"], str) and auth["key_id"] == hashlib.sha256(key).hexdigest()
                and hmac.compare_digest(expected, auth["signature"]))
    except (OSError, ValueError, TypeError, KeyError):
        return False
