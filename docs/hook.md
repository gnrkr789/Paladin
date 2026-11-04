# Change-time checks for coding agents

Paladin can check every Python file a coding agent writes or edits, statically
and without executing anything. If the code matches a known CVE pattern, the
agent is told what is wrong, why, and how to fix it, before it continues.

## Claude Code

Install a project-scoped `PostToolUse` hook (global settings are never touched):

```powershell
.venv/Scripts/paladin.exe hook install --workspace C:/projects/example
```

This adds one entry to `C:/projects/example/.claude/settings.json` for the
`Write|Edit|MultiEdit` tools. Running it again replaces Paladin's entry instead
of adding a second one; other settings and hooks are preserved. A linked
`.claude` directory or `settings.json` is refused.

The hook command runs Python in isolated mode (`-I`), so modules in the checked
workspace (for example a planted `paladin/` package or `json.py`) cannot replace
Paladin; the hook also refuses to run if Paladin was imported from the
workspace. Installs made before this change used `python -m` without `-I`;
run `hook install` again to replace them. The command line uses POSIX shell
quoting, which is what Claude Code uses for hooks (Git Bash on Windows).

On each edit of a `.py` file inside the workspace:

| Result | Hook output | Effect on the agent |
|---|---|---|
| Exact CVE rule match (CVE-2022-24065 checkout, CVE-2023-5752 pip revision) | `{"decision": "block", "reason": ...}` | The turn is blocked; the agent receives CVE, file:line, cause and fix |
| One of 125 rules drafted from CVE cards whose CVE is MEDIUM, HIGH or CRITICAL and that is not held for precision (104), on a line the edit wrote | `{"decision": "block", "reason": ...}` | The turn is blocked with the CVE, its severity, line, fix and cards |
| The same rules on lines the edit did not write, LOW rules (7; blocking with `hook install --block-low`), 14 rules held for precision, or the generalized Mercurial argv rule | `additionalContext` | Advisory note with the card id; not blocked |
| Edited dependency file (requirements*.txt, pyproject.toml, uv.lock, poetry.lock, Pipfile.lock) with a pinned version in an advisory range | `additionalContext` | Review note with CVE, card title and fixed versions; not blocked |
| Unsupported (outside the workspace, link, unreadable, non-ASCII path) | `additionalContext` | Explicit "not inspected" note; never a safe claim |
| Paladin failure | `additionalContext` | "unavailable" note; never blocks |
| Clean, or not a Python file | no output | Nothing |

The message contains fixed Paladin text, paths and line numbers only; project
code is never echoed back into the agent's context. The next edit re-runs the
check, so a fixed file passes and an unfixed one is reported again.

## Codex CLI

```powershell
.venv/Scripts/paladin.exe hook install --host codex --workspace C:/projects/example
```

This writes `C:/projects/example/.codex/hooks.json` with a `PostToolUse` hook for
`apply_patch`. Codex runs project hooks only after you review and trust them
(`/hooks` in Codex); trust is bound to the hook's hash, so re-run the trust step
after reinstalling. The hook reads the file names from the patch in
`tool_input.command` (`*** Add File:`, `*** Update File:`, `*** Move to:`) and
checks up to 20 Python files. The output contract is the same as for Claude
Code. Verified with real-shaped payloads under bash, PowerShell and cmd; a real
Codex session has not been run yet. Absolute paths are written with forward
slashes so the command needs no quoting; a workspace path containing spaces is
quoted POSIX-style, which only bash accepts.

## Other agents (MCP)

`check_changes` takes workspace-relative paths and returns the same findings:

```json
{"paths": ["tools.py", "src/vcs.py"]}
```

An empty request returns `unsupported` without inspecting anything.

## Real host check

Claude Code and Codex sessions were asked to port legacy Mercurial and pickle
helpers and add a Flask YAML upload view. The hook blocked unsafe writes
(CVE-2022-24065, yaml.load) and gave a review note for pickle.loads; the agents
added `--`, switched to yaml.safe_load and restricted or authenticated the pickle
load. With the hook and MCP entries written by `hook install` and `mcp install`,
both hosts connected, searched and ran the check tools on the task folder. A new
folder's `.codex/hooks.json` runs only after the user trusts it in Codex.

Set `PALADIN_HOOK_LOG` to a file path to append each hook decision as one JSON
line (Claude Code's stream output does not include PostToolUse hook responses).

## Robustness

Malformed or oversized hook input is reported as "unavailable", never silently
allowed. Paths must be printable ASCII inside the workspace (no links or
reparse points), so control characters can never reach the agent's context.
Scanning is linear in file size; 10,000 list assignments scan in well under
the hook timeout. MCP results send rule guidance once and cap findings at 50.

## Limits

Two exact CVE rules and 104 card rules (MEDIUM and above) block; 7 LOW card
rules, 14 card rules held for precision and one generalized Mercurial rule advise; single-file,
intraprocedural, syntactic matching. A clean result is not a security verdict.
