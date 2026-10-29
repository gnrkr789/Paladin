"""Claude Code PostToolUse hook adapter for change-time checks.

Exact CVE rule matches block the turn so the agent fixes them; review-level
findings and unsupported or failed checks are reported as additional context and
never block. Output contains fixed Paladin text, paths and line numbers only.
"""
import datetime
import json
import os
from pathlib import Path
import shlex
import stat
import tempfile

from paladin.change_check import check_paths

EDIT_TOOLS = {"Write", "Edit", "MultiEdit"}
HOOK_MATCHER = "Write|Edit|MultiEdit"
HOOK_MARKER = "hook claude-code"
MAX_REASON = 4000
MAX_PAYLOAD = 16_000_000
LOG_VARIABLE = "PALADIN_HOOK_LOG"


def _context(text):
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": text[:MAX_REASON]}}


def _describe(entry, finding, guidance):
    advice = guidance.get(finding["rule_id"], {})
    return ("- {path}:{line} {cve} [{rule}] {title}\n  Why: {cause}\n  Fix: {fix}".format(
        path=entry["path"], line=finding["line"], cve=finding["cve_id"], rule=finding["rule_id"],
        title=finding["title"], cause=advice.get("cause", ""), fix=advice.get("fix", "")))


def claude_code_hook(payload, workspace):
    """Map one hook payload to hook output; None means allow silently."""
    try:
        if not isinstance(payload, dict) or payload.get("tool_name") not in EDIT_TOOLS:
            return None
        tool_input = payload.get("tool_input")
        if not isinstance(tool_input, dict) or not isinstance(tool_input.get("file_path"), str):
            return None
        raw = tool_input["file_path"]
        if not raw.lower().endswith(".py"):
            return None
        result = check_paths(Path(workspace), [raw])
        entry, guidance = result["files"][0], result["guidance"]
    except Exception as exc:  # The hook must never break the agent turn.
        return _context("Paladin change check unavailable ({}); no result for this edit.".format(
            type(exc).__name__))
    if entry["status"] == "unsupported":
        return _context("Paladin change check unsupported for this file ({}); it was not inspected.".format(
            "; ".join(entry["notes"]) or "unsupported"))
    blocking = [finding for finding in entry["findings"] if finding["severity"] == "block"]
    review = [finding for finding in entry["findings"] if finding["severity"] != "block"]
    parse_note = ("The file could not be fully parsed; only token-level checks ran."
                  if entry.get("parse_failed") else None)
    if blocking:
        lines = ["Paladin found code matching a known CVE pattern. Fix it before continuing:"]
        lines += [_describe(entry, finding, guidance) for finding in blocking]
        if review:
            lines.append("Also review:")
            lines += [_describe(entry, finding, guidance) for finding in review]
        lines += [parse_note] if parse_note else []
        lines.append("Static check of this file only; re-checked on the next edit.")
        return {"decision": "block", "reason": "\n".join(lines)[:MAX_REASON]}
    if review:
        lines = ["Paladin review finding (not blocking; static pattern match, not a confirmed vulnerability):"]
        lines += [_describe(entry, finding, guidance) for finding in review]
        lines += [parse_note] if parse_note else []
        return _context("\n".join(lines))
    if parse_note:
        return _context("Paladin change check is incomplete for this file: " + parse_note)
    return None


def _log(path, payload, output):
    """Optional evidence log; only enabled when PALADIN_HOOK_LOG names a file."""
    tool_input = payload.get("tool_input") if isinstance(payload, dict) else None
    record = {"time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
              "tool_name": payload.get("tool_name") if isinstance(payload, dict) else None,
              "file_path": tool_input.get("file_path") if isinstance(tool_input, dict) else None,
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


def main(workspace, stream_in, stream_out):
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
            output = claude_code_hook(payload, workspace)
        except (ValueError, UnicodeError):
            output = _context("Paladin change check unavailable (invalid hook payload); no result for this edit.")
    if os.environ.get(LOG_VARIABLE):
        _log(os.environ[LOG_VARIABLE], payload, output)
    if output is not None:
        stream_out.write(json.dumps(output, ensure_ascii=True))
    return 0


def _linked(path):
    info = os.lstat(path)
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def install_claude_code(workspace, command):
    """Add one project-scoped PostToolUse hook entry; global settings are never touched."""
    workspace = Path(workspace).resolve()
    directory = workspace / ".claude"
    if os.path.lexists(directory) and (_linked(directory) or not directory.is_dir()):
        raise ValueError("unsafe_settings_directory")
    directory.mkdir(exist_ok=True)
    if not directory.resolve().is_relative_to(workspace):
        raise ValueError("unsafe_settings_directory")
    path = directory / "settings.json"
    if os.path.lexists(path) and (_linked(path) or not path.is_file()):
        raise ValueError("unsafe_settings_file")
    try:
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except ValueError as exc:
        raise ValueError("invalid_settings") from exc
    if not isinstance(data, dict) or not isinstance(data.get("hooks", {}), dict):
        raise ValueError("invalid_settings")
    line = (" ".join(shlex.quote(str(part)) for part in command) + " " + HOOK_MARKER
            + " --workspace " + shlex.quote(workspace.as_posix()))
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
                  if not (isinstance(hook, dict) and HOOK_MARKER in str(hook.get("command", "")))]
        if others:
            kept.append(dict(group, hooks=others))
    hooks["PostToolUse"] = kept + [{"matcher": HOOK_MATCHER,
                                    "hooks": [{"type": "command", "command": line, "timeout": 10}]}]
    descriptor, temporary = tempfile.mkstemp(prefix="settings-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {"status": "installed", "settings": str(path), "command": line}
