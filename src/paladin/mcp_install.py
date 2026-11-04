"""MCP registration and the paladin skill for Claude Code and Codex.

Two scopes:
- project (`paladin mcp install --workspace DIR`): .mcp.json or .codex/config.toml in the project,
  with the server fixed to that project, and the skill in the project's skills folder.
- user (`paladin mcp install --user`): one registration for every project. The server has no
  fixed workspace; the host starts it in the open project. The skill runs only when the user
  calls it: /paladin in Claude Code (disable-model-invocation), $paladin in Codex
  (allow_implicit_invocation: false).

The server reads the project for checks and the Paladin home for search.
"""
import json
import os
from importlib import resources
from pathlib import Path
import shutil
import subprocess
import tomllib

from paladin.settings_files import linked, replace_text, safe_file

BEGIN = "# BEGIN paladin (managed by paladin mcp install)"
END = "# END paladin"
SKILL_DIRS = {"claude-code": Path(".claude") / "skills", "codex": Path(".agents") / "skills"}
USAGE = {"claude-code": "/paladin", "codex": "$paladin"}
CODEX_POLICY = """interface:
  display_name: "Paladin"
  short_description: "Check the project for known CVE patterns and vulnerable pins"
policy:
  allow_implicit_invocation: false
"""
SERVER_NAME = "paladin"


def _server(command, workspace=None):
    parts = [Path(part).as_posix() if os.path.isabs(str(part)) else str(part) for part in command]
    args = parts[1:] + ["mcp"]
    return parts[0], args + ["--workspace", workspace.as_posix()] if workspace is not None else args


def _claude_project(workspace, executable, args):
    path = safe_file(workspace, ".mcp.json")
    try:
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except ValueError as exc:
        raise ValueError("invalid_settings") from exc
    if not isinstance(data, dict) or not isinstance(data.get("mcpServers", {}), dict):
        raise ValueError("invalid_settings")
    data.setdefault("mcpServers", {})[SERVER_NAME] = {"command": executable, "args": args}
    replace_text(path, json.dumps(data, indent=2) + "\n")
    return path, "Claude Code asks once to approve a project MCP server from .mcp.json."


def _without_block(text):
    if BEGIN in text and END in text:
        start, end = text.index(BEGIN), text.index(END) + len(END)
        text = (text[:start] + text[end:].lstrip("\n")).rstrip("\n")
        text = text + "\n" if text else ""
    return text


def _codex_config(base, relative, executable, args):
    path = safe_file(base, relative)
    text = _without_block(path.read_text(encoding="utf-8") if path.exists() else "")
    try:
        if SERVER_NAME in (tomllib.loads(text).get("mcp_servers") or {}):
            raise ValueError("existing_unmanaged_entry")
    except tomllib.TOMLDecodeError as exc:
        raise ValueError("invalid_settings") from exc
    # ensure_ascii=False: TOML rejects the surrogate-pair escapes json uses outside the BMP.
    block = "\n".join([BEGIN, "[mcp_servers.paladin]", "command = " + json.dumps(executable, ensure_ascii=False),
                       "args = " + json.dumps(args, ensure_ascii=False), END, ""])
    updated = (text + "\n" if text and not text.endswith("\n\n") else text) + block
    tomllib.loads(updated)
    replace_text(path, updated)
    return path


def _skill_text(host):
    text = resources.files("paladin").joinpath("resources", "paladin-skill.md").read_text(encoding="utf-8")
    if host == "claude-code":  # Only the user's /paladin runs it, never the model on its own.
        head, sep, rest = text.partition("\n---\n")
        text = head + "\ndisable-model-invocation: true" + sep + rest
    return text


def _skill(base, skills, host):
    """Write the skill under base/skills/paladin; returns the SKILL.md path."""
    path = safe_file(base, skills / "paladin" / "SKILL.md")
    replace_text(path, _skill_text(host))
    if host == "codex":
        replace_text(safe_file(base, skills / "paladin" / "agents" / "openai.yaml"), CODEX_POLICY)
    return path


def install(workspace, command, host):
    """Project scope: the server is fixed to this project."""
    if not Path(workspace).is_dir():
        raise ValueError("invalid_workspace")
    workspace = Path(workspace).resolve()
    executable, args = _server(command, workspace)
    skill = _skill(workspace, SKILL_DIRS[host], host)  # First: a refused skills folder leaves no half-done registration.
    if host == "claude-code":
        path, next_step = _claude_project(workspace, executable, args)
    else:
        path = _codex_config(workspace, Path(".codex") / "config.toml", executable, args)
        next_step = "Codex reads a project's .codex/config.toml only for a trusted project; trust it in Codex first."
    return {"status": "installed", "scope": "project", "host": host, "settings": str(path), "skill": str(skill),
            "command": [executable, *args], "next_step": next_step, "usage": USAGE[host]}


def _claude_home():
    return Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude")


def _codex_home():
    return Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex")


def _claude_cli(run, *args):
    executable = shutil.which("claude") or "claude"
    try:
        return run([executable, "mcp", *args], capture_output=True, text=True, encoding="utf-8",
                   errors="replace", timeout=60)
    except FileNotFoundError as exc:
        raise ValueError("claude_cli_not_found") from exc
    except subprocess.TimeoutExpired as exc:
        raise ValueError("claude_cli_timeout") from exc


def _printable(text, limit=200):
    return "".join(char if 0x20 <= ord(char) < 0x7F else " " for char in text).strip()[:limit]


def _claude_existing(run):
    """Preflight before anything is written: the CLI runs, and any paladin server is Paladin's.

    The claude CLI cannot mark an entry as managed, so a user server named paladin is replaced
    only when it already runs paladin.cli; anything else is refused, as for Codex.
    """
    existing = _claude_cli(run, "get", SERVER_NAME)
    if existing.returncode == 0 and "paladin.cli" not in existing.stdout:
        raise ValueError("existing_unmanaged_entry")
    return existing.returncode == 0


def _claude_register(run, executable, args, existing):
    if existing:
        _claude_cli(run, "remove", "--scope", "user", SERVER_NAME)
    added = _claude_cli(run, "add-json", "--scope", "user", SERVER_NAME,
                        json.dumps({"type": "stdio", "command": executable, "args": args}))
    if added.returncode:
        raise ValueError("claude_mcp_add_failed: " + _printable(added.stderr or added.stdout))


def install_user(command, host, run=subprocess.run):
    """User scope: every project, used only when the user calls the skill."""
    executable, args = _server(command)
    existing = _claude_existing(run) if host == "claude-code" else False
    # The skill goes first: a refused skills folder must leave no server registered.
    skills = _claude_home() if host == "claude-code" else Path.home() / ".agents"
    skill = _skill(skills.parent, Path(skills.name) / "skills", host)
    if host == "claude-code":
        # User MCP servers live in Claude Code's own state file; its CLI is the supported writer.
        try:
            _claude_register(run, executable, args, existing)
        except ValueError:
            _remove_skill(skill.parent)  # No skill without its server.
            raise
        settings = "claude mcp (user scope)"
        next_step = "Start a new Claude Code session in a project and run /paladin."
    else:
        home = _codex_home()
        settings = str(_codex_config(home.parent, Path(home.name) / "config.toml", executable, args))
        next_step = "Start a new Codex session in a project and run $paladin."
    return {"status": "installed", "scope": "user", "host": host, "settings": settings, "skill": str(skill),
            "command": [executable, *args], "next_step": next_step, "usage": USAGE[host]}


def _remove_skill(folder):
    for relative in (Path("agents") / "openai.yaml", Path("SKILL.md")):
        path = folder / relative
        if os.path.lexists(path) and not linked(path):
            path.unlink()
    for directory in (folder / "agents", folder):
        if directory.is_dir() and not linked(directory) and not any(directory.iterdir()):
            directory.rmdir()


def uninstall_user(host, run=subprocess.run):
    if host == "claude-code":
        _remove_skill(_claude_home() / "skills" / "paladin")
        try:
            removed = _claude_cli(run, "remove", "--scope", "user", SERVER_NAME)
            server = "removed" if removed.returncode == 0 else "not_registered"
        except ValueError as exc:
            server = str(exc)
        return {"status": "removed", "scope": "user", "host": host, "server": server}
    else:
        home = _codex_home()
        path = home / "config.toml"
        if path.exists() and not linked(path):
            replace_text(path, _without_block(path.read_text(encoding="utf-8")))
        _remove_skill(Path.home() / ".agents" / "skills" / "paladin")
    return {"status": "removed", "scope": "user", "host": host, "server": "removed"}
