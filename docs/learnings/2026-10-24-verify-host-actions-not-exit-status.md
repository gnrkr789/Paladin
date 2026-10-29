---
title: Verify actual host edits and tests before accepting an integration gate
scope: project
confidence: low
first_seen: 2026-10-24
seen: 1
tags: [codex, integration, permissions, evidence]
---

**Cue:** A nested real Codex task exits successfully after advisory MCP calls.

**Lesson:** Treat the host exit code, completed tool transport, actual file edit,
functional test result and security capability as separate assertions. Explicit
permission flags alone do not prove the effective tool policy allowed an edit.

**Evidence:** The first M4 CLI run exited 0 and used all four Paladin tools, but
host.stderr recorded a read-only patch rejection and a blocked test command.
The file remained identical to baseline. After explicit user approval, one
invocation-local --approve-for-me retry produced a real file_change event and
8/8 independent test passes. Both attempts observed check_changes unsupported;
the host labeled that expected MCP error result failed. Original evidence is in
docs/evidence/m4/ and retry-001/.

**How to apply:** Preserve the failed trace, inspect event arguments/results,
require evidence retrieval before the edit, verify file hashes and independent
tests, and report unsupported inspection honestly. Do not apply the fix in the
parent to substitute for a blocked host edit. The precise source of the first
read-only restriction was not established; changed permission mode, new task
directory and explicit user approval are candidate differences, not a proven
single root cause. Never infer blocking or prevention effectiveness from this
one explicitly prompted synthetic CLI task.
