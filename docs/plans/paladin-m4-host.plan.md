# Plan: M4 bounded real Codex task

Status: complete
Approved: 2026-10-24; user requested proceeding after the M3 checkpoint.
Retry approved: 2026-10-24; adjust invocation-local host permission policy and retry the same task once.
Complexity: Medium
Parent: docs/plans/paladin-cve-prevention.plan.md

## Scope

Run one actual Codex CLI task with the existing advisory MCP server. Use only
invocation-local MCP configuration, preserving global host configuration and
existing authoritative knowledge. Do not install hooks or implement blocking.
Stop after M4 evidence and report; M5 is not authorized.

The test target is an isolated Python directory-containment example under
`.cache/m4-task/`. It is not a CVE reproduction or production application.
The agent may edit only the example module and must consult Paladin before
editing. Retain valid cases and correct sibling-prefix/traversal mistakes.

## Behavior and completion criteria

| ID | Given / When | Required outcome |
|---|---|---|
| H1 | Existing prepared pack and actual Codex task | Host initializes Paladin and records real MCP calls/results. |
| H2 | Path-containment intent | Agent calls status, search and pinned evidence before editing; cites actual returned conditions in its explanation. |
| H3 | Deliberately incomplete prefix predicate | Baseline behavior tests fail; agent corrects it and independent functional tests pass, retaining valid paths. |
| H4 | Advisory check capability | Agent observes unsupported change inspection and reports no approval, blocking or passing receipt. |
| H5 | Task ends or fails | Preserve raw host JSONL, final message, before/after code and test results; inspect actual content, not exit code alone. |
| H6 | Corpus/model/index identity | No ingestion/reindex/model change; manifest and authoritative files remain unchanged. |

## Execution

1. Capture baseline fixture and failing behavior tests before an agent edits it.
2. Configure only Paladin stdio for the single CLI invocation; keep the default
   selected model and record the observed host/model identity where available.
3. Run `codex exec --json` in the task directory, capturing stdout/stderr and a
   final message. No global MCP registration, new app chat, push or publication.
4. Independently verify the resulting module, fixed tests, retained ordinary
   behavior and tool-result use. Record failure instead of simulating calls if
   host/authentication or MCP compatibility fails.
5. Write docs/evidence/m4-report.md and docs/evidence/m4/ artifacts, then stop.

Bound the agent run to five minutes with one diagnosis/fix/retry if startup or
integration fails. No automatic expansion to more tasks, comparative eval,
model migration, source ingestion or host enforcement. Prompted tool use in one
CLI run is evidence only for that run, not automatic desktop integration,
tool-call guarantees, bypass resistance or prevention effectiveness.

## Current checkpoint

Actual CLI MCP status/search/evidence/check calls and result consumption are
verified. The first host edit/test was rejected by read-only policy. The user
approved adjustment and one retry. The documented --approve-for-me mode then
allowed the actual host edit and tests; all eight independent tests passed both
inside the task and separately afterward. Global configuration, source/model/
index fingerprints and test files were preserved. The initial failure remains
separate from retry evidence. See docs/evidence/m4-report.md. Stop before M5;
this does not authorize further experiments or claim enforcement effectiveness.

## Validation

Use Python unittest on the isolated behavior fixture before/after; inspect MCP
call arguments/results and chronology in actual Codex JSONL. No broad M3 suite
repeat is needed unless M3 implementation changes. Preserve baseline and failed
attempts. Rules and corpus fixtures remain specification_only/source_observed.

## Risks and limits

The task code and returned advisory evidence enter the Codex model context.
Only synthetic example code is used. No credentials are printed/copied. Reuse
the host's existing ChatGPT login through the normal CLI. Sandbox limitations
and any missing provider/home configuration are reported separately from MCP
functionality. CLI evidence does not prove desktop UI behavior.
