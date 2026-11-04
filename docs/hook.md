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
| One of 125 rules drafted from CVE cards whose CVE is MEDIUM, HIGH or CRITICAL (118), on a line the edit wrote | `{"decision": "block", "reason": ...}` | The turn is blocked with the CVE, its severity, line, fix and cards |
| The same rules on lines the edit did not write, LOW rules (7; blocking with `hook install --block-low`), or the generalized Mercurial argv rule | `additionalContext` | Advisory note with the card id; not blocked |
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

`docs/evidence/change-hook/host-run-2.jsonl`: a Claude Code session was asked to
port a legacy function verbatim. It wrote `['hg', 'checkout', branch]`; the hook
blocked the turn with CVE-2022-24065; the agent changed it to
`['hg', 'checkout', '--', branch]` and explained the change (4 turns). In
`host-run-1.jsonl` the model wrote the protected form on its own, so the hook had
nothing to report. `host-run-3.jsonl` repeats run 2 with `PALADIN_HOOK_LOG` set;
`host-run-3.hook-log.jsonl` records Paladin's own block output. In that run the
agent explained the CVE and proposed the one-line fix but left the file
verbatim, following the prompt's "exactly as written, then stop". The hook
informs and blocks the turn; it does not edit code itself.

`docs/evidence/agent-e2e-v2/` (pack v2, 2026-11-03, scripts/run_agent_e2e.py): one
task asked each agent to port the legacy Mercurial and pickle helpers, add a Flask
YAML upload view, and use Paladin search. Claude Code (Sonnet 5.5): the hook blocked
the first write with CVE-2022-24065 and a pickle review note; the agent added `--`,
replaced pickle.loads with a restricted unpickler, used yaml.safe_load, called search
7 times, and the final static check is clean. Codex (gpt-6.1-sol): runs 1-3 never ran the project hook: a new folder's
`.codex/hooks.json` runs only after the user trusts it (trust is stored per hooks
file in the user's Codex config), and those runs used a fresh folder each time.
Run 4 used this checkout's trusted hook; it fired on every edit but refused, as
designed, because Paladin is imported from that workspace. Run 5 used a folder
outside the checkout whose hook the user trusted with `/hooks`, with the user's
own Codex config and no trust bypass: the hook blocked the first patch with
CVE-2022-24065 plus a pickle review note, the agent added `--`, used
yaml.safe_load, and kept pickle.loads documented as trusted-only. In both hosts
the MCP check tools reported the task files as unreadable, because the MCP server
was started on the Paladin checkout (where the search index lives), not on the task
folder; search itself worked.

Installed registration (2026-11-03, `--installed-mcp`): Claude Code run 3 and Codex
run 7 read Paladin's MCP entry from the files `paladin mcp install` wrote (.mcp.json,
enabled the way approving it records; .codex/config.toml in the trusted folder), with no
MCP configuration passed on the command line. Both connected, searched, and ran
check_changes on the task folder (Codex also check_dependencies). Claude Code was blocked
on CVE-2022-24065 and fixed it; Codex wrote the `--` form itself and got the pickle
review note.

Set `PALADIN_HOOK_LOG` to a file path to append each hook decision as one JSON
line (Claude Code's stream output does not include PostToolUse hook responses).

## Robustness

Malformed or oversized hook input is reported as "unavailable", never silently
allowed. Paths must be printable ASCII inside the workspace (no links or
reparse points), so control characters can never reach the agent's context.
Scanning is linear in file size; 10,000 list assignments scan in well under
the hook timeout. MCP results send rule guidance once and cap findings at 50.

## Limits

Two exact CVE rules and 118 card rules (MEDIUM and above) block, 7 LOW card
rules and one generalized Mercurial rule advise; single-file,
intraprocedural, syntactic matching. A clean result is not a security verdict.
