"""End-to-end check with real agents on pack v2: change hook, MCP search, and the agent's fix.

Usage: python -B scripts/run_agent_e2e.py {claude,codex} [--run NAME]
Creates a fresh task folder under .cache/agent-e2e/, installs Paladin's project hook there,
serves Paladin's MCP tools for search, and runs one headless session with the same task
prompt. Hook decisions go to a PALADIN_HOOK_LOG file. Evidence (session stream, hook log,
final files and a summary with the final static check) goes to docs/evidence/agent-e2e-v2/.
No user or global agent settings are changed.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from paladin.change_check import check_paths  # noqa: E402

PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
TIMEOUT = 1800
LEGACY = """import pickle
import subprocess


def switch(branch):
    subprocess.check_output(['hg', 'checkout', branch])


def load_cached(blob):
    return pickle.loads(blob)
"""
PROMPT = """Work only inside the current folder. Use English.

1. Create app/legacy_tools.py by porting these legacy helpers; keep their behavior:

{legacy}
2. Create app/views.py with a Flask view import_settings that accepts an uploaded YAML
   settings file and returns the parsed settings as JSON.
3. Before you finish, call the paladin MCP tool search_prevention_patterns to look up
   known CVE patterns related to what you wrote, and fix anything that applies.
   If a Paladin hook reports a finding after an edit, address it too.
4. End with a short summary: which Paladin findings and cards you saw, and what you changed.
""".format(legacy="\n".join("   " + line for line in LEGACY.splitlines()))


def mcp_server():
    return {"command": str(PYTHON), "args": ["-I", "-m", "paladin.cli", "mcp", "--workspace", str(ROOT)]}


def run_claude(task, log):
    config = task.parent / (task.name + "-mcp.json")
    config.write_text(json.dumps({"mcpServers": {"paladin": mcp_server()}}), encoding="utf-8")
    command = ["claude", "-p", "--model", "claude-sonnet-5-5", "--output-format", "stream-json", "--verbose",
               "--mcp-config", str(config), "--strict-mcp-config", "--setting-sources", "project",
               "--permission-mode", "acceptEdits", "--allowedTools", "mcp__paladin__search_prevention_patterns",
               "--no-session-persistence"]
    return command, PROMPT


def run_codex(task, log):
    server = mcp_server()
    command = ["codex", "exec", "-m", "gpt-6.1-sol", "-s", "workspace-write", "--skip-git-repo-check",
               "--ephemeral", "--ignore-rules", "--ignore-user-config", "--dangerously-bypass-hook-trust", "--json",
               "-C", str(task), "-c", "windows.sandbox=\"elevated\"",
               # Codex loads a project's .codex/hooks.json only for a trusted project, as after /hooks.
               "-c", "projects.'{}'.trust_level=\"trusted\"".format(str(task).lower()),
               "-c", "mcp_servers.paladin.command=" + json.dumps(server["command"]),
               "-c", "mcp_servers.paladin.args=" + json.dumps(server["args"]), "-"]
    return command, PROMPT


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("host", choices=["claude", "codex"])
    parser.add_argument("--run", default="run-1")
    args = parser.parse_args(argv)
    task = ROOT / ".cache" / "agent-e2e" / args.host / args.run
    evidence = ROOT / "docs" / "evidence" / "agent-e2e-v2" / args.host / args.run
    if task.exists() or evidence.exists():
        raise SystemExit("run exists; pick a new --run name")
    (task / "app").mkdir(parents=True)
    evidence.mkdir(parents=True)
    (task / "app" / "__init__.py").write_text("", encoding="ascii")
    host = "claude-code" if args.host == "claude" else "codex"
    subprocess.run([str(PYTHON), "-I", "-m", "paladin.cli", "hook", "install", "--host", host, "--workspace", str(task)],
                   check=True, capture_output=True)
    log = evidence / "hook-log.jsonl"
    command, prompt = (run_claude if args.host == "claude" else run_codex)(task, log)
    env = dict(os.environ, PALADIN_HOOK_LOG=str(log))
    done = subprocess.run(command, input=prompt, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          cwd=task, env=env, timeout=TIMEOUT, shell=sys.platform == "win32")
    (evidence / "session.jsonl").write_text(done.stdout, encoding="utf-8", newline="\n")
    (evidence / "session.stderr.txt").write_text(done.stderr[-20000:], encoding="utf-8", newline="\n")
    files = sorted(path for path in (task / "app").glob("*.py") if path.stat().st_size)
    for path in files:
        shutil.copyfile(path, evidence / path.name)
    final = check_paths(task, [path.relative_to(task).as_posix() for path in files])
    hooks = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []
    summary = {"host": args.host, "exit": done.returncode, "files": [path.name for path in files],
               "hook_decisions": hooks, "mcp_calls": done.stdout.count("search_prevention_patterns"),
               "final_check": final}
    (evidence / "summary.json").write_text(json.dumps(summary, indent=1, default=str) + "\n", encoding="utf-8",
                                           newline="\n")
    print(json.dumps({key: summary[key] for key in ("host", "exit", "files", "mcp_calls")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
