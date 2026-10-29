"""Bounded, read-only source observations for Mercurial checkout arguments."""

import ast
import hashlib
import io
import os
from pathlib import Path
import stat
import tokenize

from .language import require_english
from .pip_case_adapter import CVE_ID as PIP_CVE_ID, RULE_ID as PIP_RULE_ID, revision_lists

RULE_ID = "CVE-2022-24065:mercurial-checkout-v1"
MAX_FILES = 5000
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 20_000_000


def _reparse(info):
    return bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _text(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _calls(tree):
    aliases = {"subprocess"}
    functions = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            aliases.update(alias.asname or alias.name for alias in node.names if alias.name == "subprocess")
        elif isinstance(node, ast.ImportFrom) and node.module == "subprocess":
            functions.update(alias.asname or alias.name for alias in node.names if alias.name in {"run", "Popen", "call", "check_call", "check_output"})
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        is_process = (isinstance(func, ast.Name) and func.id in functions) or (
            isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
            and func.value.id in aliases and func.attr in {"run", "Popen", "call", "check_call", "check_output"})
        if is_process:
            yield node


def _analyze(tree):
    lines, unsupported = [], []
    for call in _calls(tree):
        argv = call.args[0] if call.args else next((k.value for k in call.keywords if k.arg == "args"), None)
        if not isinstance(argv, (ast.List, ast.Tuple)):
            unsupported.append("dynamic subprocess argv at line %d" % call.lineno)
            continue
        parts = argv.elts
        if len(parts) < 2:
            if any(isinstance(part, ast.Starred) for part in parts):
                unsupported.append("expanded subprocess argv at line %d" % call.lineno)
            continue
        if _text(parts[1]) is None:
            unsupported.append("dynamic subprocess subcommand at line %d" % call.lineno)
            continue
        if _text(parts[1]) != "checkout":
            continue
        executable = _text(parts[0])
        if executable is not None and executable not in {"hg", "mercurial"}:
            continue
        if executable is None and not isinstance(parts[0], ast.Name):
            unsupported.append("dynamic checkout executable at line %d" % call.lineno)
            continue
        for arg in parts[2:]:
            if _text(arg) == "--":
                break
            if isinstance(arg, ast.Starred):
                unsupported.append("expanded checkout argv at line %d" % call.lineno)
                break
            if isinstance(arg, ast.Constant):
                continue
            if isinstance(arg, ast.Name):
                lines.append(call.lineno)
                break
            unsupported.append("dynamic checkout argument at line %d" % call.lineno)
            break
    return lines, unsupported


def scan_project(root):
    """Return source candidates, not vulnerability verdicts; never execute target code."""
    root = Path(root).absolute()
    require_english(str(root))
    info = root.lstat()
    if _reparse(info) or stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ValueError("Project root must be a non-link directory")
    candidates, unsupported = [], []
    limitations = ["Static local source patterns only; candidates do not prove reachability or a vulnerability.",
                   "Only the CVE-2022-24065 checkout and CVE-2023-5752 pip revision rules are supported.",
                   "No interprocedural data flow or runtime behavior is analyzed.",
                   "Concurrent filesystem changes can affect scan coverage."]
    files = total = directories = 0
    stopped = False
    def walk_error(_error):
        unsupported.append("directory inaccessible")

    for directory, dirs, names in os.walk(root, topdown=True, followlinks=False, onerror=walk_error):
        directories += 1
        if directories > MAX_FILES:
            unsupported.append("directory count limit exceeded")
            break
        dirs.sort()
        names.sort()
        for name in list(dirs):
            if name in {".git", ".paladin", "__pycache__"}:
                dirs.remove(name)
                continue
            path = Path(directory) / name
            try:
                item = path.lstat()
                if _reparse(item) or stat.S_ISLNK(item.st_mode):
                    dirs.remove(name)
                    unsupported.append("link directory skipped")
            except OSError:
                dirs.remove(name)
                unsupported.append("directory inaccessible")
        for name in names:
            if not name.endswith(".py"):
                continue
            files += 1
            if files > MAX_FILES:
                unsupported.append("file count limit exceeded")
                stopped = True
                break
            path = Path(directory) / name
            rel = path.relative_to(root).as_posix()
            try:
                require_english(rel)
            except ValueError:
                unsupported.append("non-ASCII source path skipped")
                continue
            try:
                before = path.lstat()
                if _reparse(before) or not stat.S_ISREG(before.st_mode):
                    unsupported.append("non-regular source skipped: " + rel)
                    continue
                if before.st_size > MAX_FILE_BYTES or total + before.st_size > MAX_TOTAL_BYTES:
                    unsupported.append("source size limit exceeded: " + rel)
                    continue
                flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(path, flags)
                with os.fdopen(fd, "rb") as stream:
                    after = os.fstat(stream.fileno())
                    if _reparse(after) or not stat.S_ISREG(after.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                        raise OSError("source changed")
                    data = stream.read(MAX_FILE_BYTES + 1)
                if len(data) > MAX_FILE_BYTES or total + len(data) > MAX_TOTAL_BYTES:
                    unsupported.append("source size limit exceeded: " + rel)
                    continue
                total += len(data)
                encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
                tree = ast.parse(data.decode(encoding), filename=rel)
            except (OSError, UnicodeError, SyntaxError, ValueError, LookupError):
                unsupported.append("source unreadable or unsupported syntax: " + rel)
                continue
            digest = hashlib.sha256(data).hexdigest()
            lines, unknown = _analyze(tree)
            unsupported.extend(rel + ": " + message for message in unknown)
            for line in lines:
                identity = "\0".join((RULE_ID, rel, str(line), digest)).encode("ascii")
                candidates.append({"rule_id": RULE_ID, "cve_id": "CVE-2022-24065", "path": rel,
                                   "line": line, "source_sha256": digest,
                                   "candidate_id": hashlib.sha256(identity).hexdigest()})
            for value in revision_lists(tree):
                line = value.lineno
                identity = "\0".join((PIP_RULE_ID, rel, str(line), digest)).encode("ascii")
                candidates.append({"rule_id": PIP_RULE_ID, "cve_id": PIP_CVE_ID, "path": rel,
                                   "line": line, "source_sha256": digest,
                                   "candidate_id": hashlib.sha256(identity).hexdigest()})
        if stopped:
            break
    return {"status": "partial" if unsupported else "complete", "candidates": candidates,
            "unsupported_patterns": unsupported, "limitations": limitations}
