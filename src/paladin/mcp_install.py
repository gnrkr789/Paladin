"""Project-scoped MCP registration for Claude Code (.mcp.json) and Codex (.codex/config.toml).

User-level agent settings are never touched. The server reads the project for checks and the
Paladin home for search, so one registration per project is enough.
"""
import json
import os
from pathlib import Path
import tomllib

from paladin.settings_files import replace_text, safe_file

BEGIN = "# BEGIN paladin (managed by paladin mcp install)"
END = "# END paladin"


def _server(workspace, command):
    parts = [Path(part).as_posix() if os.path.isabs(str(part)) else str(part) for part in command]
    return parts[0], parts[1:] + ["mcp", "--workspace", workspace.as_posix()]


def _claude_code(workspace, executable, args):
    path = safe_file(workspace, ".mcp.json")
    try:
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except ValueError as exc:
        raise ValueError("invalid_settings") from exc
    if not isinstance(data, dict) or not isinstance(data.get("mcpServers", {}), dict):
        raise ValueError("invalid_settings")
    data.setdefault("mcpServers", {})["paladin"] = {"command": executable, "args": args}
    replace_text(path, json.dumps(data, indent=2) + "\n")
    return path, "Claude Code asks once to approve a project MCP server from .mcp.json."


def _codex(workspace, executable, args):
    path = safe_file(workspace, Path(".codex") / "config.toml")
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    if BEGIN in text and END in text:
        start, end = text.index(BEGIN), text.index(END) + len(END)
        text = (text[:start] + text[end:].lstrip("\n")).rstrip("\n")
        text = text + "\n" if text else ""
    try:
        if "paladin" in (tomllib.loads(text).get("mcp_servers") or {}):
            raise ValueError("existing_unmanaged_entry")
    except tomllib.TOMLDecodeError as exc:
        raise ValueError("invalid_settings") from exc
    # ensure_ascii=False: TOML rejects the surrogate-pair escapes json uses outside the BMP.
    block = "\n".join([BEGIN, "[mcp_servers.paladin]", "command = " + json.dumps(executable, ensure_ascii=False),
                       "args = " + json.dumps(args, ensure_ascii=False), END, ""])
    updated = (text + "\n" if text and not text.endswith("\n\n") else text) + block
    tomllib.loads(updated)
    replace_text(path, updated)
    return path, "Codex reads a project's .codex/config.toml only for a trusted project; trust it in Codex first."


def install(workspace, command, host):
    if not Path(workspace).is_dir():
        raise ValueError("invalid_workspace")
    workspace = Path(workspace).resolve()
    executable, args = _server(workspace, command)
    path, next_step = (_claude_code if host == "claude-code" else _codex)(workspace, executable, args)
    return {"status": "installed", "host": host, "settings": str(path), "command": [executable, *args],
            "next_step": next_step}
