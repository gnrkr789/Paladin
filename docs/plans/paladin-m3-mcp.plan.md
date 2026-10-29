# Plan: M3 bounded advisory MCP

Status: complete
Approved: 2026-10-23; implement M3, verify acceptance, stop before M4.
Complexity: Medium
Selected Milestone: M3
Parent plan: docs/plans/paladin-cve-prevention.plan.md
Prepared: 2026-10-23 Asia/Seoul

## Summary

Expose the existing M2 advisory knowledge through a local stdio MCP server.
An MCP client can discover tools, search for prevention references, retrieve
bounded local evidence, and inspect readiness without changing knowledge state.
M3 establishes a working protocol surface; actual Codex task behavior is M4.

The user approved this scope on 2026-10-23. Implement and verify M3, report the
result, and stop before M4.

## Requirements

- Add `paladin mcp --workspace PATH`; bind one resolved workspace at startup.
  Tool arguments cannot select another workspace or an arbitrary path or URL.
- Use the official Python MCP SDK and stdio only. Resolve and lock an exact
  compatible SDK release during implementation; record the SDK and negotiated
  protocol revision in evidence. Do not assume a legacy FastMCP import works.
- Preserve the existing 30-card pack, pack bytes/hash, model weights, encoder
  identity, semantic collection and diagnostic collection.
- Apply `english-ascii-v1` to all tool-supplied text before pack/model/DB access.
  Validate types, lengths, enums and unknown fields without coercion. Reject
  Boolean values used as integers. Provenance bytes remain outside this policy.
- Reuse `search_patterns`, `load_pack`, `knowledge_status`, existing source
  hashes and read-only SQLite access. No automatic setup, indexing, download,
  ingestion, approval, deletion, Docker control or arbitrary execution.
- Keep execution status separate from advisory judgment. Every domain result
  includes `security_ready=false`, `enforcement_enabled=false` and
  `sharing_enabled=false`. Never promote source observations or fixture specs.
- Document that evidence returned to a cloud agent enters that agent's context.
- Out of scope: source-code/diff inspection, dependency version resolution,
  rules, passing receipts, blocking, hooks, host configuration changes,
  autonomous Codex tasks, new corpus/model work, sharing and M5 evaluation.

## Tool contracts

All tools declare object input/output schemas. Responses use structured content
plus a compatible JSON text representation of the same result. Stdout carries
protocol messages only; diagnostics go to stderr without logging query/evidence
body text. Tool annotations describe read-only behavior and no open-world access;
annotations are hints, not access-control enforcement.

| Tool | Inputs | Result |
|---|---|---|
| `search_prevention_patterns` | `intent`: nonempty English text, <=20,000 UTF-8 bytes; `stack`: defaults to `python_web`, only supported value; `family`: optional existing family; `limit`: integer 1..20, default 5 | Bounded advisory cards with cause, prerequisites, prevention, limitations, similarity, evidence IDs and pinned pack/encoder identity. No installed-package applicability claim. |
| `get_pattern_evidence` | `pattern_id`: CVE-shaped ID; `pack_sha256`: required revision pin; `evidence_ids`: optional list of at most 4 IDs belonging to that pattern | Source URL, relative location, hash, optional anchor, source-review/fixture state, and bounded verified local excerpts where available. |
| `get_knowledge_status` | Empty object | Pack ID/hash/date, supported stack/families, text policy, model/index/DB readiness and failures, semantic manifest, disabled capabilities and evidence-content availability. Pack date is not an upstream freshness guarantee. |
| `check_changes` | Empty object for this M3 capability probe | Always `unsupported`, with `reason=rules_not_validated`, `inspection_performed=false`, no safety judgment and no receipt. No diff, files or caller project are read. |

The parent plan proposes stack/packages search and actual change inspection.
This milestone deliberately supports only the existing Python stack/family
filters. Package filters are not advertised or silently ignored. `check_changes`
is an explicit capability boundary until reviewed and executed rules exist.

### Identity, errors and limits

- Pattern revision is the bundled pack SHA-256, not a new invented per-card
  revision. Evidence ID is `kind:sha256`, scoped to its pattern and pack hash.
  Derive IDs without editing the source pack. Search returns them for follow-up.
- Wrong pack pin returns `unsupported` with `reason=pack_revision_mismatch`.
  Unknown valid pattern/evidence IDs return `unsupported` with a specific reason.
  Invalid syntax, unknown fields and unsupported characters are rejected.
- Preserve `complete`, `invalid_request`, `unsupported`, `unavailable` from the
  core. Add `partial` only for explicitly omitted/truncated evidence/results.
  Preserve empty successful search as `judgment=no_known_match`; failures must
  never take that path. Status tool reports `ready` as operational readiness.
- Malformed protocol messages and unknown tools use MCP protocol errors.
  Malformed tool arguments use bounded application schema errors; domain failures return a
  structured tool result with `isError=true` for invalid_request, unavailable or
  unsupported. Partial useful data has `isError=false` and explicit omissions.
  An unavailable status probe is also a domain error with diagnostic data.
- The serialized CallToolResult, including both structured and text copies, is
  at most 64 KiB. Trim at item/line boundaries before serialization; include
  omitted counts/reasons. If the minimal envelope cannot fit, return a bounded
  unavailable error. Do not silently truncate a prerequisite or safety limit.
- Evidence defaults to metadata only; add `include_excerpt` Boolean, default
  false, and `max_excerpt_bytes` integer 1..16384, default 4096, to its schema.
  At most 4 evidence entries and 16 KiB of excerpt data total per call, subject
  to the overall response cap. Report returned line ranges and truncation.
- Request processing has a 30-second wall deadline, including cold model load
  and database calls; permit one backend operation at a time. Enforce deadline
  and shutdown using cancellable execution with bounded cleanup. Cancelling a
  wait without stopping its worker is insufficient. Record the tested cleanup
  tolerance and do not accumulate background workers after timeouts.
- Tool argument JSON has a 32 KiB budget. This is an application limit, not a
  claim that the SDK rejects arbitrarily large transport frames before parsing.

### Evidence access

Only resolve pack-listed snapshots below `data/m0/sources` or `data/m2/sources`
within the startup workspace. Reject path escape, symlinks and Windows junction
escape, including substituted pack metadata in tests. Do not accept caller file
paths, follow evidence URLs, or execute content. Hash the complete source bytes
before returning an excerpt; cap source reads at 4 MiB per file and report larger
files as omitted. Select the stored anchor where present, otherwise initial
lines. Preserve original source characters and label excerpts as untrusted data.

The installed wheel intentionally excludes original snapshots. Metadata-only
requests can complete there without a model or DB. Requested excerpts missing
from disk yield `partial` with metadata and `content_unavailable`; mismatched or
unsafe files yield no excerpt and an explicit integrity/access omission. A fully
verified excerpt never implies reproduction or redistribution clearance.

## Behavior

| ID | Scenario | Given | When | Then |
|---|---|---|---|---|
| S1 | Discovery | Server launched for a fixed workspace | A real SDK client connects and lists tools | The four schemas above are discoverable; protocol output is clean. |
| S2 | Advisory search | Current model/index and valid English intent | Search is called | Core ranking is retained with bounded references, identity and advisory limits. |
| S3 | Invalid input | Bad types, unknown fields, oversized/empty text or escaped Unicode | Any tool is called | Rejection precedes model/DB access; no translated or coerced input. |
| S4 | Unsupported scope | Unsupported stack/family or check capability request | Tool is called | Explicit unsupported result; no source inspection, receipt or safety verdict. |
| S5 | Backend failure | Missing model/DB, stale manifest or backend exception | Search/status runs | Bounded unavailable diagnostics; no no_known_match or safety pass. |
| S6 | Evidence identity | Valid pattern, pack pin and evidence IDs | Metadata is requested | Only linked evidence returns, independent of model/DB availability. |
| S7 | Evidence content | Local verified source or missing/corrupt/escaping path | Excerpt is requested | Verified bounded lines or explicit omissions; no arbitrary reads/network access. |
| S8 | Budget handling | Large evidence/cards or slow backend | A call exceeds a budget | Valid bounded result and explicit partial/unavailable status; worker stops within tested tolerance. |
| S9 | Untrusted content | Evidence contains instructions or non-ASCII source bytes | Evidence is returned | Original bytes remain intact; excerpts are data and trigger no execution/fetch. |
| S10 | Read-only lifecycle | Prepared state and subprocess server | Calls finish, fail, cancel, or client exits | Server exits cleanly; no knowledge/index/model changes or orphan workers. |
| S11 | Installed artifact | Wheel installed without raw snapshots/weights | Client lists tools and requests metadata/evidence/search | Startup/discovery and metadata work; unavailable dependencies/content are reported honestly. |

Each new behavior gets a failing contract test before implementation. Mocked
domain tests and actual subprocess protocol tests are separate evidence.

## Patterns to Mirror

| Category | Source | Pattern |
|---|---|---|
| Naming/CLI | `src/paladin/cli.py:main` | argparse subcommands, workspace option, lazy core imports |
| Errors | `src/paladin/knowledge.py:search_patterns` and `_failure` | Explicit status and bounded diagnostic text; false security readiness |
| Data access | `knowledge.py:_active_manifest`, `local.py:_verify_metadata` | Resolved workspace, matching manifests, read-only SQLite with explicit closing |
| Evidence | `scripts/audit_m2_sources.py:audit` | Root allowlist, hash and patch-anchor checks; strengthen for bounded serving |
| Language | `src/paladin/language.py:require_english` | Shared deterministic ASCII contract |
| Tests | `tests/test_m2_semantic.py:M2Contracts` | unittest, temporary directories and dependency seams |
| Logging | No MCP logging convention exists | Use stderr; test stdout purity at process boundary |

## Files to Change

| File | Action | Why |
|---|---|---|
| `src/paladin/mcp_server.py` | CREATE | SDK registration, schemas, bounded transport adapter and lifecycle |
| `src/paladin/advisory.py` | CREATE | Read-only response shaping, evidence IDs/access and budgets |
| `src/paladin/cli.py` | UPDATE | Add mcp launch command without setup side effects |
| `pyproject.toml`, `uv.lock` | UPDATE | Lock official SDK dependency |
| `tests/test_m3_mcp.py` | CREATE | New domain and real subprocess protocol behavior tests |
| `scripts/smoke_m3.py` | CREATE | Bounded real-backend protocol evidence capture |
| `docs/mcp.md`, `docs/evidence/m3-report.md` | CREATE | Tool contracts, startup, results and integration boundaries |
| `docs/evidence/m3/` | CREATE | Bounded schema, smoke, timeout and package artifacts |
| `README.md`, `docs/plans/paladin-cve-prevention.plan.md` | UPDATE | Actual delivered interface and milestone evidence after completion |

Avoid core changes unless needed for validation order, deadlines or read-only
reuse. Do not rewrite pack, historical results or original evidence.

## Tasks

1. Freeze SDK/protocol compatibility and schemas. Add failing S1/S3/S4/S6 tests.
2. Implement advisory shaping, identity and safe evidence serving (S2/S5-S9).
3. Add stdio entry point, deadlines and shutdown; exercise real SDK subprocess
   calls, stderr/stdout separation and process cleanup (S1/S8/S10).
4. Run the existing suite once with the new tests, M0/source audits, and a single
   bounded real-backend smoke through MCP. Build/install a wheel into a temporary
   workspace environment and exercise S11. Document results and stop at M3.

## Validation and stop conditions

- Offline: `python -B -m unittest discover -s tests -v`,
  `python -B scripts/validate_m0.py`, `python -B scripts/audit_m2_sources.py`.
  Use the workspace `.venv/Scripts/python.exe`, not global Python.
- Protocol: real official SDK client subprocess discovery and all four calls;
  controlled failure, timeout/cancel and clean disconnect tests. Assertions must
  inspect schemas, payloads, limits and worker lifecycle, not exit codes alone.
- Live smoke: existing prepared semantic state; status, one English UNC-path
  search, evidence metadata/excerpt and unsupported check. No Docker restart,
  reseed, reindex, model download or full M2/M5 evaluation to repeat prior work.
- Package smoke: wheel contains server modules/resources, excludes source
  snapshots/weights, and supports metadata-only mode without them.
- Record test output, negotiated protocol/SDK versions, live response identity,
  actual response sizes, timing and cleanup tolerance in `docs/evidence/m3/`.
- If live dependencies are unavailable, preserve evidence and report that gate
  unmet. Do not repeatedly repair infrastructure or claim full M3 completion.
  Allow one bounded diagnosis/fix/retry for a failing M3 smoke, then review.

## Risks

| Risk | Mitigation |
|---|---|
| SDK/API changes | Pin a verified release; test real transport and record negotiation. |
| Long synchronous ONNX/Milvus work | Enforce wall deadline with worker termination and prove cleanup. |
| Raw snapshots absent from wheel | Separate metadata availability from excerpt availability. |
| Response size duplication | Measure full serialized MCP result including both representations. |
| Evidence text treated as instructions | Data labels, no executable/network interface, provenance preservation. |
| Advisory/check confusion | Unsupported check with no receipt; M4/M5 claims remain pending. |

## Acceptance

- [x] S1-S11 have meaningful tests, with recorded failing-to-passing evidence.
- [x] Existing 57-test baseline and M0/source audits remain passing.
- [x] Actual subprocess tool discovery/calls, error mapping, response limits,
  deadline enforcement and cleanup pass.
- [x] One real local MCP search/evidence/status smoke passes with pinned pack
  and encoder identity; CLI ranking and knowledge state are preserved.
- [x] Installed-wheel metadata and missing-content behavior pass.
- [x] Documentation includes exact startup command, English-only inputs, local
  evidence boundaries and the explicit absence of inspection/blocking.
- [x] User can review the M3 report before any M4 host work begins.

## Verified Facts

Initial planning inspection found core search/status and shared ASCII validation,
with no MCP dependency/server or evidence IDs. The preserved pack identifies 30 cards
with SHA-256 `9c8e61c9641c80936b7aeeeadff3a4f6ce400a914810410f5d3480dcca8adecd`.
Source files have hashes and optional line anchors. The wheel excludes raw
snapshots/weights. Implementation verified SDK 2.3.0 with default protocol
2026-07-28 and legacy 2025-06-18, 74 tests, real local calls and installed-wheel
behavior. See docs/evidence/m3-report.md for exact evidence and limits.

## Review Decisions

- Fixed strict integer acceptance and worker cleanup serialization after failing
  contract tests exposed both issues.
- Application-side schema validation returns bounded invalid-request tool results
  instead of allowing validator diagnostics to echo arbitrary user input.
- Kept one killable worker per backend call; warm caching is deferred.
- Completed M3 only. The parent plan's `building` status does not authorize M4.

## Protocol references

- https://modelcontextprotocol.io/specification/2025-06-18/server/tools
- https://modelcontextprotocol.io/specification/2025-06-18/basic/transports
- https://github.com/modelcontextprotocol/python-sdk

Checked during planning on 2026-10-23. Use the pinned SDK's supported protocol
negotiation and verify the actual client boundary during implementation; these
references are not evidence of Codex host integration.
