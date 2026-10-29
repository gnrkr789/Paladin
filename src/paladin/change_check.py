"""Static, per-file change checks against known CVE source patterns.

Nothing is executed. Findings reuse the project scanner on the exact bytes read
and carry fixed Paladin text only, so project content is never echoed back to an
agent as instructions.
"""
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat

from paladin.candidate_scan import MAX_FILE_BYTES, RULE_ID, scan_source
from paladin.hg_argv_rule import RULE_ID as GENERAL_RULE_ID
from paladin.pip_case_adapter import RULE_ID as PIP_RULE_ID

MAX_PATHS = 20
# Bounded response: guidance text is sent once per rule, findings are capped.
MAX_FINDINGS = 50
PARSE_FAILURE = "source unreadable or unsupported syntax"
GUIDANCE = {
    RULE_ID: {
        "severity": "block",
        "title": "Mercurial checkout target can be parsed as an option",
        "cause": ("A non-constant checkout value is passed to hg as its own argument. Mercurial parses "
                  "options such as --config and --debugger anywhere in argv, so a value starting with "
                  "'-' can change what hg executes (CVE-2022-24065)."),
        "fix": ("Insert '--' before the checkout value for Mercurial, for example "
                "[repo_type, 'checkout', '--', value]; keep Git argument handling unchanged."),
    },
    PIP_RULE_ID: {
        "severity": "block",
        "title": "Mercurial revision is passed as a separate argument",
        "cause": ("get_base_rev_args returns ['-r', rev]; a revision such as '--config=...' is then parsed "
                  "by Mercurial as an option (CVE-2023-5752)."),
        "fix": ("Attach the revision to its option: return ['--rev=' + rev]. Do not use '-r=' + rev, "
                "which Mercurial parses as the revision '=VALUE'."),
    },
    GENERAL_RULE_ID: {
        "severity": "review",
        "title": "Non-constant value reaches hg checkout/update before '--'",
        "cause": ("A value that can start with '-' reaches a Mercurial checkout/update argument list "
                  "without an option terminator, the shape behind CVE-2022-24065 and CVE-2023-5752."),
        "fix": ("If the value can come from configuration, URLs or users, pass '--' before it or attach it "
                "to its option ('--rev=' + value). This is a review finding, not a confirmed vulnerability."),
    },
}


def _entry(path, status, notes=(), sha=None, findings=()):
    return {"path": path, "status": status, "sha256": sha, "findings": list(findings), "notes": list(notes)}


def _relative(roots, absolute):
    for root in roots:
        try:
            return root, absolute.relative_to(root)
        except ValueError:
            continue
    raise ValueError("path outside workspace")


def _resolve(root, raw):
    """Return (relative posix path, absolute path) inside root, or raise ValueError."""
    # Printable ASCII only: control characters in a path could shape agent-visible text.
    if not isinstance(raw, str) or not raw or any(not 0x20 <= ord(char) < 0x7F for char in raw):
        raise ValueError("unsupported path")
    candidate = Path(raw)
    if not candidate.is_absolute():
        parts = PurePosixPath(raw.replace("\\", "/")).parts
        if any(part in ("..", "") for part in parts):
            raise ValueError("path outside workspace")
        candidate = root / raw
    absolute = Path(os.path.abspath(candidate))
    # The workspace or the reported file path may use a junction or 8.3 alias; compare
    # real paths too. A link inside the workspace that leaves it is still rejected.
    try:
        root, relative = _relative([root, root.resolve()], absolute)
    except ValueError:
        absolute = Path(os.path.realpath(absolute))
        root, relative = _relative([root.resolve()], absolute)
    current = root
    for part in relative.parts:
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("linked path")
    return relative.as_posix(), absolute


def check_file(root, raw):
    root = Path(os.path.abspath(root))
    try:
        rel, path = _resolve(root, raw)
    except (ValueError, OSError) as exc:
        printable = isinstance(raw, str) and all(0x20 <= ord(char) < 0x7F for char in raw)
        return _entry(raw if printable else None, "unsupported",
                      [str(exc) if isinstance(exc, ValueError) else "path unreadable"])
    if not rel.lower().endswith(".py"):
        return _entry(rel, "skipped", ["not a Python source file"])
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
            return _entry(rel, "unsupported", ["not a regular file or larger than the size limit"])
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                return _entry(rel, "unsupported", ["file changed while it was opened"])
            data = stream.read(MAX_FILE_BYTES + 1)
    except OSError:
        return _entry(rel, "unsupported", ["file unreadable"])
    if len(data) > MAX_FILE_BYTES:
        return _entry(rel, "unsupported", ["file larger than the size limit"])
    candidates, notes = scan_source(rel, data)
    findings = [{"rule_id": item["rule_id"], "cve_id": item["cve_id"], "line": item["line"],
                 "severity": GUIDANCE[item["rule_id"]]["severity"], "title": GUIDANCE[item["rule_id"]]["title"]}
                for item in sorted(candidates, key=lambda item: item["line"])]
    status = "findings" if findings else ("partial" if notes else "clean")
    entry = _entry(rel, status, notes, hashlib.sha256(data).hexdigest(), findings)
    entry["parse_failed"] = any(note.startswith(PARSE_FAILURE) for note in notes)
    return entry


def check_paths(root, paths):
    """Check up to MAX_PATHS files; the overall status never upgrades partial results."""
    if not isinstance(paths, list) or not paths or len(paths) > MAX_PATHS:
        return {"status": "invalid_request", "files": []}
    files = [check_file(root, raw) for raw in paths]
    remaining, truncated = MAX_FINDINGS, False
    for item in files:
        if len(item["findings"]) > remaining:
            item["findings"] = item["findings"][:remaining]
            item["notes"].append("findings truncated to the response limit")
            truncated = True
        remaining -= len(item["findings"])
    used = {finding["rule_id"] for item in files for finding in item["findings"]}
    statuses = {item["status"] for item in files}
    if "findings" in statuses:
        status = "findings"
    elif statuses & {"partial", "unsupported"}:
        status = "partial"
    else:
        status = "clean"
    return {"status": status, "files": files, "truncated": truncated,
            "guidance": {rule: {"cause": GUIDANCE[rule]["cause"], "fix": GUIDANCE[rule]["fix"]}
                         for rule in sorted(used)},
            "limitations": ["Static, single-file pattern checks for two Mercurial CVE shapes only.",
                            "A clean result is not a security verdict."]}
