# Plan: Change-time CVE pattern check through agent hooks

Status: draft
Done:

## Summary

When a coding agent writes or edits Python code, a host hook passes the changed
file to Paladin. Paladin statically checks it against known CVE source patterns,
without executing anything. A match returns a bounded, evidence-grounded finding
(CVE, cause, the exact lines, a deterministic fix where one exists, and the
upstream patch reference) so the agent fixes it in the same session. After the
fix, the next edit re-runs the check and the finding disappears. Exact rule
matches can block the turn; similarity-only hints never block.

First host: Claude Code `PostToolUse` hooks (Write, Edit, MultiEdit), returning
`{"decision": "block", "reason": ...}` so the reason is fed back to the agent.
Codex: the `check_changes` MCP tool (currently an "unsupported" probe) becomes a
real per-file check, and Codex hook support is verified during the build before
any claim is made.

## Behavior

| ID | Given | When | Then |
|---|---|---|---|
| S1 | an edit adds `subprocess.check_output(["hg", "checkout", branch])` | the PostToolUse hook runs | the hook blocks with CVE-2022-24065, the line, cause and the `--` fix; nothing is executed |
| S2 | the agent applies the fix (`["hg", "checkout", "--", branch]`) | the hook runs again | no finding; the hook allows |
| S3 | an edit adds `return ["-r", rev]` in a Mercurial revision helper | hook runs | blocks with CVE-2023-5752 and the `--rev=` fix |
| S4 | a wrapper call `self.run(["hg", "update", "-r", rev])` (held-out miss) | hook runs | reported as a `review` finding (generalized hg argv rule) with no automatic fix and no block |
| S5 | a non-Python file, an unreadable file, a path outside the workspace or non-ASCII path | hook runs | allows with an explicit `unsupported` note; never a "safe" claim |
| S6 | constant arguments only (`["hg", "update", "default"]`) | hook runs | no finding |
| S7 | Paladin itself fails (timeout, parse error, internal error) | hook runs | the hook does not block, reports `unavailable`, and exits within its time budget |
| S8 | hook input names a file whose content changed between edit and check | hook runs | checks the bytes it read, reports their hash; no TOCTOU claim beyond that |
| S9 | the same finding was already reported for the same file hash | hook runs again without change | finding is repeated, not suppressed (no silent pass) |
| S10 | `check_changes` MCP call with workspace-relative paths | agent calls it | returns the same findings as the hook for those files |
| S11 | an installed wheel | `paladin hook install --host claude-code --scope project` | writes a project `.claude/settings.json` hook entry only after an explicit command; never edits global settings |

## Tasks

- T1 (S1-S3, S6): `paladin.change_check.check_file(root, path)` reusing the
  two exact rules from `candidate_scan` on one file; finding objects with
  CVE card data from the prevention pack and the deterministic fix preview.
- T2 (S4): generalized `hg` argv rule (any call whose first list element is
  `"hg"` and second is `checkout`/`update`, with a non-constant argument before
  any `--`), severity `review`, no block, no fix. Held-out projects used to
  shape it are no longer held out; a new held-out set is required afterwards.
- T3 (S1, S2, S5, S7-S9): `paladin hook claude-code` stdin/stdout adapter with
  a strict input schema, workspace containment, 5 s budget, ASCII output.
- T4 (S10): implement `check_changes` over T1 with bounded output.
- T5 (S11): `paladin hook install` writing project-scope settings only.
- T6: real host check: one Claude Code session in a scratch project where an
  edit triggers the block and the agent fixes it; recorded transcript and hook
  log. Codex hook support checked and reported, not assumed.

## Risks

- False positives annoy agents; only exact rules block, generalized rules advise.
- Hook output is fed into the model: findings must be fixed Paladin text plus
  quoted line numbers, never project text interpreted as instructions.
- Static matching on one file misses inter-procedural flows (documented).
- Coverage is two CVE rules plus one generalized rule; this is not general
  vulnerability prevention.

## Validation

```
.venv/Scripts/python.exe -B -m unittest discover -s tests -v
.venv/Scripts/python.exe -I scripts/run_heldout_eval.py
```
Plus the T6 host transcript.
