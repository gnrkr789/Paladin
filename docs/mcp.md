# M3 advisory MCP

Paladin exposes local advisory knowledge over stdio using the official Python
MCP SDK, pinned to `mcp==2.3.0`. All domain responses retain
`security_ready=false`, `enforcement_enabled=false` and `sharing_enabled=false`.

## Start

After installing the locked dependencies, launch from the project directory:

```powershell
.\.venv\Scripts\paladin.exe mcp --workspace 'C:\Users\user\Desktop\personal\Paladin'
```

Register it in a project instead of editing agent settings by hand:

```powershell
.\.venv\Scripts\paladin.exe mcp install --workspace C:/projects/example              # Claude Code: .mcp.json
.\.venv\Scripts\paladin.exe mcp install --host codex --workspace C:/projects/example # Codex: .codex/config.toml
```

Other servers in those files stay; Paladin's entry is replaced on reinstall, and a
hand-written `mcp_servers.paladin` table in the Codex config is refused rather than
overwritten. User-level settings are never touched.

The MCP client owns the process and supplies stdin/stdout. There is no HTTP
listener. Stdout carries protocol messages only. Launch performs no setup,
download, indexing or Docker control. Prepare semantic retrieval with the
explicit administrative commands in [knowledge](knowledge.md) first.

`--workspace` is the project the check tools read (check_changes, check_project,
check_dependencies, scan_cve_candidates). Evidence excerpts and guidance come from
the evidence copies shipped with Paladin; verified cases come from the home. Search and status
read the Paladin home (`--home`, else `PALADIN_HOME`, else the per-user data
folder), where `setup`, `model prepare` and `patterns index` put the index, so one
setup serves every project.

Both folders resolve once at startup; tool arguments cannot change them. No
arbitrary SQL, query expression, file path, URL fetch or shell command is exposed.
Actual Codex registration and task behavior remain M4. No host configuration or
hooks are installed; a client can ignore or bypass advisory tools.

## Tools

| Tool | Inputs | Output |
|---|---|---|
| `search_prevention_patterns` | Required `intent`; optional `stack=python_web`, `family`, `limit=5` | Ranked advisory cards, prerequisites, prevention, limitations, evidence IDs and semantic manifest |
| `get_pattern_evidence` | Required `pattern_id`, `pack_sha256`; optional `evidence_ids`, `include_excerpt=false`, `max_excerpt_bytes=4096` | Linked provenance, source review and fixture specifications; optional verified local excerpts |
| `get_knowledge_status` | Empty object | Pack identity/date, supported scope, text policy, semantic readiness, separate diagnostic/DB checks and source-content availability |
| `check_changes` | Required `paths` (up to 20 workspace-relative Python files) | Static findings per file (block or review), with CVE, severity, line and fix; `outcome` is `findings` or `clean` |
| `check_project` | Empty object | The same checks on every project Python file (virtual environments, installed packages and hidden folders skipped): `checked_files`, `totals`, files with findings (blocking first), each rule's title and fix once under `rules`; trimmed to the response budget when large |
| `scan_cve_candidates` | Empty object; configured workspace is the scan root | Source locations for the supported CVE-2022-24065 checkout rule; partial coverage is explicit; candidates require verification |
| `check_dependencies` | Optional `paths` (workspace-relative dependency files) | Pinned versions in requirements*.txt, pyproject.toml, uv.lock, poetry.lock or Pipfile.lock that fall in a collected PyPI advisory range, with CVE, card title and fixed versions; unpinned requirements are listed, not judged |
| `get_prevention_guidance` | Required `pattern_id`, `pack_sha256`, `guidance_sha256`; optional `include_patch_context` | Conditional correction, verified patch context on request, and policy-checked local case references when present |

`paladin mcp install` also writes the `paladin` skill (`.claude/skills/paladin/` for
Claude Code, `.agents/skills/paladin/` for Codex): `/paladin` or `$paladin` runs
`check_project` and `check_dependencies` and reports the findings without editing code.

Discovery publishes input/output schemas and read-only annotations. Annotations
describe intent; code restrictions establish access. Results provide structured
content and an equivalent JSON text block.

Search supports only Python web backends. Families: `path_traversal`,
`sql_injection`, `ssrf`, `command_injection`, `unsafe_deserialization`. Package
filters are not accepted and installed version applicability is not computed.
Limit is an integer from 1 to 20; Booleans, floats and numeric strings are rejected.

```json
{"intent":"Windows UNC paths in safe_join","limit":1,"family":"path_traversal"}
```

Use the returned manifest's `pack_sha256`, pattern ID and evidence IDs for
follow-up. Pattern revision is the pack hash. Evidence IDs are `kind:sha256`,
scoped to that pattern and pack. Old revisions and unknown IDs are explicitly
unsupported; they are not substituted silently.

## Boundaries and limits

- All supplied text values and keys use `english-ascii-v1`: printable ASCII,
  tabs and line breaks. Unsupported characters, invalid types, empty intent and
  unknown fields fail before pack/model/DB access. There is no translation or
  language classification. Upstream provenance remains verbatim.
- Intent is at most 20,000 bytes; argument JSON has a 32 KiB application budget.
  This is not a pre-parse transport-frame/memory guarantee for malformed or
  arbitrarily large protocol input.
- Serialized tool results are at most 64 KiB including both content copies;
  512 bytes are reserved for SDK envelope metadata. Omit whole cards/evidence
  entries with `partial`, omitted count and reason. Never silently cut individual
  prerequisites or limitations.
- At most four evidence IDs, 16 KiB per excerpt and 16 KiB total excerpt data.
  Return whole UTF-8 lines, returned ranges and explicit truncation. An oversized
  first line returns no lines rather than an incomplete line.
- Backend calls have a 30-second wall deadline including queue time, startup,
  model loading and DB access. One backend worker runs at a time, including
  cleanup. Timeout/cancellation kills and reaps it, with two seconds for cleanup.
  The actual default timeout completed in 30.016 seconds during verification.
- Each backend call uses a fresh process/model session. Warm caching is deferred.

`complete`/`partial` describe execution, not safety. Successful empty search
preserves `judgment=no_known_match`. Missing/stale model/index/DB and timeout yield
`unavailable`. Operational `ready` is not security approval. Domain failures
(`invalid_request`, `unsupported`, `unavailable`) set MCP `isError=true`; useful
partial data sets it false. Unknown tools and malformed protocol requests use
protocol errors. Application schema failures return bounded invalid-request tool
errors without echoing user input in SDK validator diagnostics.

## Evidence access

Metadata-only evidence requires no model, DB or raw snapshots. Excerpts read only
pack-listed files below `data/m0/sources` or `data/m2/sources` inside the startup
workspace. Reject path escapes, symlinks and reparse points/junctions. Sources
larger than 4 MiB are omitted. Verify the complete file hash before returning
lines; stored anchors select preferred lines. Missing files, hash mismatch,
unsafe paths and truncation produce explicit omissions.

Preserve original upstream characters and label excerpts `untrusted_source_data`.
Never execute instructions or fetch URLs from evidence. These path checks are
not a hardened sandbox against an administrator concurrently replacing files.
Worker stdout is private; diagnostics do not log intent or evidence body text.

Wheels exclude snapshots and model weights. Installed wheels can discover tools
and return metadata without them. Requested missing excerpts yield `partial`
with `content_unavailable`; unprepared search/status is `unavailable`. Pack date
and source presence do not prove upstream freshness, applicability or rights.
Returning evidence to a cloud agent places it in that agent's context.

Cards remain `source_observed`/`agent_source_comparison`; fixtures remain
`specification_only`, and affected versions remain unnormalized source claims.
Human approval, executed detection rules, receipts, blocking and effectiveness
evaluation remain pending. See the [M3 evidence report](evidence/m3-report.md).

The optional bounded smoke runner writes only its chosen report and never
registers a host or advances to M4:

```powershell
.\.venv\Scripts\python.exe -B scripts/smoke_m3.py --mode live --output .cache/m3-live.json
```
