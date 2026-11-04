"""Claude Code PostToolUse hook adapter for change-time checks.

Exact CVE rule matches block the turn so the agent fixes them; rules drafted from CVE
cards block by CVE severity (MEDIUM and above, LOW with --block-low) on the lines an
edit wrote. Other findings and unsupported or failed checks are reported as additional
context and never block. Output contains fixed Paladin text, paths and line numbers only.
"""
import datetime
import json
import os
from pathlib import Path
import re
import shlex

from paladin.change_check import check_paths, line_digest
from paladin.dependency_check import is_dependency_file
from paladin.settings_files import replace_text, safe_file

EDIT_TOOLS = {"Write", "Edit", "MultiEdit"}
HOOK_MATCHER = "Write|Edit|MultiEdit"
HOOK_MARKER = "hook claude-code"
MAX_REASON = 4000
MAX_REVIEW = 1500
MAX_PAYLOAD = 16_000_000
LOG_VARIABLE = "PALADIN_HOOK_LOG"


def _context(text):
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": text[:MAX_REASON]}}


def _describe(entry, finding, guidance):
    advice = guidance.get(finding["rule_id"], {})
    if "cve_ids" in finding:  # A rule drafted from CVE cards: its own fix, severity and cards.
        return "- {path}:{line} {cve} ({level}) [{rule}] {title}\n  Fix: {fix}\n  Cards: {cards}".format(
            path=entry["path"], line=finding["line"], cve=finding["cve_id"], level=finding.get("cve_severity"),
            rule=finding["rule_id"], title=finding["title"], fix=finding["fix"], cards=", ".join(finding["cve_ids"]))
    return ("- {path}:{line} {cve} [{rule}] {title}\n  Why: {cause}\n  Fix: {fix}".format(
        path=entry["path"], line=finding["line"], cve=finding["cve_id"], rule=finding["rule_id"],
        title=finding["title"], cause=advice.get("cause", ""), fix=advice.get("fix", "")))


def _brief(entry, finding, guidance):
    fix = finding.get("fix") or guidance.get(finding["rule_id"], {}).get("fix", "")
    return "- {path}:{line} [{rule}] {title}. Fix: {fix} Card: {cards}".format(
        path=entry["path"], line=finding["line"], rule=finding["rule_id"], title=finding["title"], fix=fix,
        cards=", ".join(finding.get("cve_ids") or [finding["cve_id"]]))


def _bounded(header, items, tail):
    """Header plus as many review lines as fit in MAX_REVIEW, then a count of the rest."""
    text = header
    for index, line in enumerate(items):
        rest = "\n... and {} more review findings.".format(len(items) - index)
        if len(text) + 1 + len(line) + len(rest) + len(tail) > MAX_REVIEW:
            return text + rest + tail
        text += "\n" + line
    return text + tail


def _respond(entries, guidance, written=None):
    """Shared PostToolUse output for one or more checked files; None means allow silently.

    written lists, per entry, digests of the lines this edit wrote (None: the whole file).
    Review findings are reported only on those lines. Exact CVE rules block on any line; card
    rules block on written lines and are reported as review on the others.
    """
    written = written or [None] * len(entries)
    unsupported = [entry for entry in entries if entry["status"] == "unsupported"]
    def wrote(lines, finding):
        return lines is None or finding.get("line_sha") in lines

    # Exact CVE rules block wherever they match; card rules block only on lines this edit wrote,
    # so old code in a file does not stop every later edit (it is reported as review instead).
    blocking = [(entry, finding) for entry, lines in zip(entries, written) for finding in entry["findings"]
                if finding["severity"] == "block" and ("cve_ids" not in finding or wrote(lines, finding))]
    review = [(entry, finding) for entry, lines in zip(entries, written) for finding in entry["findings"]
              if (entry, finding) not in blocking and (wrote(lines, finding) or finding["severity"] == "block")]
    notes = ["Not inspected (unsupported): {} ({}).".format(entry["path"] or "unsupported path",
                                             "; ".join(entry["notes"]) or "unsupported")
             for entry in unsupported]
    notes += ["{} could not be fully parsed; only token-level checks ran.".format(entry["path"])
              for entry in entries if entry.get("parse_failed")]
    if blocking:
        lines = ["Paladin found code matching a known CVE pattern. Fix it before continuing:"]
        lines += [_describe(entry, finding, guidance) for entry, finding in blocking]
        if review:
            lines.append("Also review:")
            lines += [_brief(entry, finding, guidance) for entry, finding in review]
        lines += notes
        lines.append("Static check of the changed files only; re-checked on the next edit.")
        return {"decision": "block", "reason": "\n".join(lines)[:MAX_REASON]}
    if review:
        header = "Paladin review finding (not blocking; static pattern match, not a confirmed vulnerability):"
        tail = "".join("\n" + note for note in notes)
        return _context(_bounded(header, [_brief(entry, finding, guidance) for entry, finding in review], tail))
    if notes:
        return _context("Paladin change check is incomplete. " + " ".join(notes))
    return None


def _written(texts):
    return {line_digest(line) for text in texts if isinstance(text, str) for line in text.splitlines()}


def _check(workspace, paths, written=None, block_low=False):
    try:
        result = check_paths(Path(workspace), paths, block_low)
        return _respond(result["files"], result["guidance"], written)
    except Exception as exc:  # The hook must never break the agent turn.
        return _context("Paladin change check unavailable ({}); no result for this edit.".format(
            type(exc).__name__))


def _dependencies(workspace, paths):
    """Review note for edited dependency files whose pinned versions are in an advisory range."""
    try:
        from paladin.dependency_check import check_workspace
        result = check_workspace(Path(workspace), paths)
    except Exception as exc:  # The hook must never break the agent turn.
        return _context("Paladin dependency check unavailable ({}); no result for this edit.".format(
            type(exc).__name__))
    if not result["findings"]:
        notes = result["notes"]
        return _context("Paladin dependency check is incomplete. " + " ".join(notes)) if notes else None
    header = ("Paladin dependency finding (not blocking; the pinned version is in an advisory's affected range, "
              "which does not show the vulnerable feature is used):")
    lines = ["- {}:{} {} {} is affected by {}: {}. Fixed in: {}.".format(
        f["file"], f["line"] or "-", f["package"], f["version"], f["cve_id"], f["title"],
        ", ".join(f["fixed_in"]) or "no fixed version listed") for f in result["findings"]]
    return _context(_bounded(header, lines, ""))


def _combine(first, second):
    """One hook output from a code check and a dependency check; a block keeps its decision."""
    if not first or not second:
        return first or second
    extra = second["hookSpecificOutput"]["additionalContext"]
    if "decision" in first:
        return dict(first, reason=(first["reason"] + "\n" + extra)[:MAX_REASON])
    text = first["hookSpecificOutput"]["additionalContext"] + "\n" + extra
    return _context(text)


def claude_code_hook(payload, workspace, block_low=False):
    """Claude Code Write/Edit/MultiEdit payload."""
    if not isinstance(payload, dict) or payload.get("tool_name") not in EDIT_TOOLS:
        return None
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict) or not isinstance(tool_input.get("file_path"), str):
        return None
    raw = tool_input["file_path"]
    if is_dependency_file(raw):
        return _dependencies(workspace, [raw])
    if not raw.lower().endswith(".py"):
        return None
    edits = tool_input.get("edits") if payload["tool_name"] == "MultiEdit" else [tool_input]
    texts = [edit.get("new_string") for edit in edits or [] if isinstance(edit, dict)]
    known = payload["tool_name"] != "Write" and any(isinstance(text, str) for text in texts)
    return _check(workspace, [raw], [_written(texts) if known else None], block_low)


PATCH_PATH = re.compile(r"^\*\*\* (?:Add File|Update File|Move to): (.+?)\s*$", re.M)
PATCH_FILE = re.compile(r"^\*\*\* (Add File|Update File|Delete File|Move to): (.+?)\s*$")


def patch_written(patch):
    """Per target path: digests of added lines, or None for a new file (all lines written)."""
    written, current = {}, None
    for line in patch.splitlines():
        header = PATCH_FILE.match(line)
        if header:
            kind, path = header.groups()
            if kind == "Move to" and current is not None:
                written[path] = written.get(current)
            current = path
            if kind == "Add File":
                written[path] = None
            elif kind == "Update File":
                written.setdefault(path, set())
        elif line.startswith("+") and current is not None and written.get(current) is not None:
            written[current].add(line_digest(line[1:]))
    return written


def patch_paths(patch):
    """Target paths named by a Codex apply_patch envelope, in order, without duplicates."""
    paths = []
    for match in PATCH_PATH.finditer(patch):
        if match[1] not in paths:
            paths.append(match[1])
    return paths


def _absolute(base, path):
    return path if Path(path).is_absolute() else str(Path(base) / path)


def codex_hook(payload, workspace, block_low=False):
    """Codex apply_patch payload: the patch text is tool_input.command."""
    if not isinstance(payload, dict) or payload.get("tool_name") != "apply_patch":
        return None
    tool_input = payload.get("tool_input")
    patch = tool_input.get("command") if isinstance(tool_input, dict) else tool_input
    if not isinstance(patch, str):
        return _context("Paladin change check unavailable (unrecognized apply_patch input); no result for this edit.")
    base = payload.get("cwd") if isinstance(payload.get("cwd"), str) else str(workspace)
    dependencies = [_absolute(base, path) for path in patch_paths(patch) if is_dependency_file(path)][:20]
    found = _dependencies(workspace, dependencies) if dependencies else None
    named = [path for path in patch_paths(patch) if path.lower().endswith(".py")]
    paths = [_absolute(base, path) for path in named]
    if not paths:
        return found
    if len(paths) > 20:
        return _combine(_context("Paladin change check covered the first 20 of {} Python files.".format(len(paths))),
                        found)
    written = patch_written(patch)
    return _combine(_check(workspace, paths, [written.get(path, set()) for path in named], block_low), found)


HOSTS = {"claude-code": claude_code_hook, "codex": codex_hook}


def _log(path, payload, output):
    """Optional evidence log; only enabled when PALADIN_HOOK_LOG names a file."""
    tool_input = payload.get("tool_input") if isinstance(payload, dict) else None
    record = {"time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
              "tool_name": payload.get("tool_name") if isinstance(payload, dict) else None,
              "file_path": tool_input.get("file_path") if isinstance(tool_input, dict) else None,
              "patch_paths": (patch_paths(tool_input["command"]) if isinstance(tool_input, dict)
                              and isinstance(tool_input.get("command"), str) else None),
              "output": output}
    try:
        with open(path, "a", encoding="ascii") as stream:
            stream.write(json.dumps(record, ensure_ascii=True) + "\n")
    except (OSError, TypeError, ValueError):
        pass


def _loaded_from(workspace):
    import paladin
    package = Path(paladin.__file__).resolve()
    try:
        package.relative_to(Path(workspace).resolve())
        return True
    except ValueError:
        return False


def main(workspace, stream_in, stream_out, host="claude-code", block_low=False):
    """Hook entry point: always exit 0; malformed input is reported, never silently allowed."""
    raw = stream_in.read(MAX_PAYLOAD + 1)
    payload = None
    if _loaded_from(workspace):
        output = _context("Paladin change check refused: Paladin was imported from the checked workspace.")
    elif len(raw) > MAX_PAYLOAD:
        output = _context("Paladin change check unavailable (hook payload too large); no result for this edit.")
    else:
        try:
            payload = json.loads(raw)
            output = HOSTS[host](payload, workspace, block_low)
        except (ValueError, UnicodeError):
            output = _context("Paladin change check unavailable (invalid hook payload); no result for this edit.")
    if os.environ.get(LOG_VARIABLE):
        _log(os.environ[LOG_VARIABLE], payload, output)
    if output is not None:
        stream_out.write(json.dumps(output, ensure_ascii=True))
    return 0


INSTALL_TARGETS = {"claude-code": (".claude", "settings.json", HOOK_MATCHER),
                   "codex": (".codex", "hooks.json", "apply_patch")}


def install_claude_code(workspace, command):
    return install_hook(workspace, command, "claude-code")


def install_hook(workspace, command, host, block_low=False):
    """Add one project-scoped PostToolUse hook entry; user-level settings are never touched."""
    folder, filename, matcher = INSTALL_TARGETS[host]
    workspace = Path(workspace).resolve()
    path = safe_file(workspace, Path(folder) / filename)
    try:
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except ValueError as exc:
        raise ValueError("invalid_settings") from exc
    if not isinstance(data, dict) or not isinstance(data.get("hooks", {}), dict):
        raise ValueError("invalid_settings")
    # Absolute paths with forward slashes need no quoting, so the command works in bash,
    # cmd and PowerShell alike; anything else is quoted POSIX-style.
    parts = [Path(part).as_posix() if os.path.isabs(str(part)) else str(part) for part in command]
    line = (" ".join(shlex.quote(part) for part in parts) + " hook " + host
            + " --workspace " + shlex.quote(workspace.as_posix()) + (" --block-low" if block_low else ""))
    hooks = data.setdefault("hooks", {})
    groups = hooks.get("PostToolUse", [])
    if not isinstance(groups, list):
        raise ValueError("invalid_settings")
    kept = []
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
            kept.append(group)
            continue
        # Remove only Paladin's own hook; other hooks in the same group stay.
        others = [hook for hook in group["hooks"]
                  if not (isinstance(hook, dict) and " hook " + host + " " in str(hook.get("command", "")))]
        if others:
            kept.append(dict(group, hooks=others))
    hooks["PostToolUse"] = kept + [{"matcher": matcher,
                                    "hooks": [{"type": "command", "command": line, "timeout": 10}]}]
    replace_text(path, json.dumps(data, indent=2) + "\n")
    result = {"status": "installed", "host": host, "settings": str(path), "command": line}
    if host == "codex":
        result["next_step"] = "Review and trust the project hook in Codex with /hooks; untrusted hooks do not run."
    return result
