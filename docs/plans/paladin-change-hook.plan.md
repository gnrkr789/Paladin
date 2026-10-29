# Plan: Change-time CVE pattern check through agent hooks

Status: review
Done: S1, S2, S3, S4, S5, S6, S7, S8, S9, S10, S11; T6 real host (runs 1-3)

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
| S5 | an unreadable Python file, a path outside the workspace or a non-ASCII path | hook runs | allows with an explicit `unsupported` note; never a "safe" claim. Non-Python files are skipped silently |
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
- T2 (S4): done before this plan was approved - `mercurial-argv-option-injection-v1`
  (review severity, no block, no automatic fix), measured on three held-out sets.
- T3 (S1, S2, S5, S7-S9): `paladin hook claude-code` stdin/stdout adapter with
  a strict input schema, workspace containment, 5 s budget, ASCII output.
- T4 (S10): implement `check_changes` over T1 with bounded output; an empty
  request keeps returning `unsupported` (no inspection performed).
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

## Approval

Approved by the user on 2026-10-29: start the hook after the third held-out set.

## Review Decisions (2026-10-29)

Code review: 0 CRITICAL, 0 HIGH, 3 MEDIUM. Security review: 1 CRITICAL, 1 HIGH, 4 MEDIUM.

- fixed -> (security C1) hook and MCP worker ran `python -m` with cwd = workspace, so a planted `paladin/` or stdlib-named module ran on every edit -> `-I` isolated mode in the installed hook and MCP worker; hook refuses a Paladin imported from the workspace; test_installed_hook_cannot_be_shadowed_by_workspace_modules (manual check: without -I prints PLANTED)
- fixed -> (security H1) quadratic built-list tracking (10,000 assignments ~200 s) -> growth statements indexed per name; test_many_list_assignments_scan_in_linear_time
- fixed -> (security M1) linked .claude could redirect writes to global settings -> lstat/reparse checks and containment; test_install_refuses_a_linked_settings_directory (skipped if symlinks are unavailable)
- fixed -> (security M2 / code M2) oversized or malformed hook payload allowed silently -> reported as unavailable; test_s7_hook_entry_point_reports_malformed_payloads
- fixed -> (security M3) control characters in paths could reach agent context -> printable ASCII only; test_control_characters_in_paths_are_never_echoed
- fixed -> (security M4 / code M1) many findings collapsed check_changes to unavailable -> guidance once per rule, 50-finding cap with truncated flag; test_findings_are_bounded_with_guidance_sent_once
- fixed -> (code M3) T6 evidence lacked the hook output -> PALADIN_HOOK_LOG; host-run-3.hook-log.jsonl
- fixed -> (code LOW, security L1) unparseable Python reported silently; settings merge robustness; uppercase .PY skipped -> fixed with tests
- deferred -> (security L2) POSIX-only quoting (documented); (security L3) no fstat-after-open identity check in the hook read; (security L4, code LOW) junction or 8.3 workspace aliases may report "outside workspace"
- note -> host runs 2 and 3 used the earlier command line without -I; behaviour of the check is unchanged
- result -> host run 2: agent fixed the code after the block; host run 3: agent reported the CVE and the fix but kept the file verbatim as the prompt demanded

## Review Decisions (2026-10-29, follow-up)

- done -> Codex adapter: `paladin hook codex` reads apply_patch file names from tool_input.command; `hook install --host codex` writes .codex/hooks.json (matcher apply_patch); format from the official Codex hooks documentation; tests test_codex_apply_patch_payload_is_checked_per_named_file, test_codex_install_writes_project_hooks_json; dry run under bash, PowerShell and cmd blocks correctly; a real Codex session waits for the user to trust the hook
- fixed -> (security L2) POSIX-only quoting -> absolute paths written with forward slashes and no quotes; works in bash, PowerShell and cmd (paths with spaces still bash-only, documented)
- fixed -> (security L3) lstat/open race -> O_NOFOLLOW open plus st_dev/st_ino identity check
- fixed -> (security L4, code LOW) junction or 8.3 workspace aliases -> real-path comparison fallback; links leaving the workspace are still rejected
- note -> test_m3_mcp protocol tests are timing-sensitive under machine load (failed once in a 237 s run, passed alone and in the next full run: 208 tests OK)
