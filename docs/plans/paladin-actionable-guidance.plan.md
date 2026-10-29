# Plan: Source-grounded actionable prevention guidance

Status: review
Done: S1, S2, S3, S4, S5
Size: Large

## Summary
Give coding agents short corrections with applicability conditions, behavior
to preserve, checks, and provenance. Keep raw CVE/patch snapshots for audit;
solution quality does not depend on sending full excerpts to the agent.

## Requirements
- Pilot one aligned pattern per supported family. Tie cause, prerequisite,
  correction, exception, and test to immutable source hash/line anchors;
  quarantine conflicts.
- Serve trigger, target facts to check, fix, behavior to preserve, tests,
  missing facts, provenance, and verification state. Preserve raw upstream
  claims and English ASCII authored text.
- Keep excerpt access bounded and separate from guidance. Version/hash the
  guidance pack; invalidate derived index identity on change. Similarity and
  model assertions are not security verdicts.
- **Out of scope**: changing frozen M5, automatic approval, blocking, ingestion,
  sharing, new language support, and broad rollout.
- **Decision**: five candidate corrections first; existing MCP contract stays
  intact until a new read-only guidance path passes its gates.
- **Reviewer**: the project owner selected self-review in chat. Candidates
  remain advisory until that reviewer records an explicit card-level decision.

## Behavior
- S1 conditional guidance: given aligned evidence, when guidance is requested,
  then scoped fix steps, required target facts, preservation checks, and
  provenance fit within the response budget without claiming target inspection.
- S2 uncertain: given missing or conflicting evidence or target facts, when
  guidance is requested, then the gap is named and applicability is not asserted.
- S3 truncated audit: given a long excerpt, when source is requested, then
  `partial` and omissions are explicit; guidance is not promoted by its summary.
- S4 changed evidence: given a withdrawn or changed claim, when loading, then
  stale index/approval identities fail closed.
- S5 useful fix: given vulnerable and safe fixtures, when tested, then the
  flaw is removed and legitimate behavior remains or promotion fails.

## Tasks
1. Audit five source/patch pairs and claim anchors (`scripts/audit_m2_sources.py`) -> S1, S2, S4.
2. Define versioned claim schema and approval states (`src/paladin/resources/prevention-pack.schema.json:1`) -> S1, S4.
3. Test vulnerable, safe, and preserved behavior (`tests/test_m3_mcp.py:114`) -> S2, S5.
4. Add compact read-only guidance with pinned provenance (`src/paladin/advisory.py:107`) -> S1-S3.
5. Review claims independently; evaluate on a new holdout, not M5 (`eval/m5_harness.py:91`) -> S1-S5.

## Validation
`.venv\Scripts\python.exe -B -m unittest discover -s tests -q` plus claim
anchor/hash audit, fixtures, MCP smoke, independent review, and a new holdout.

## Risks
- Concision can hide prerequisites -> require anchored review and explicit unknowns.
- Fixtures can mirror the implementation -> review independently; keep M5 disclosed.

## Verified Facts

- In this repository, the pilot source snapshots for all five families are
  available locally and S1 passes with hash-checked evidence pairs.
- The new read-only MCP tool returns five source-pinned candidate cards with
  explicit target facts, correction, preservation checks, support references,
  and candidate review state. It does not inspect a caller's code.
- The full unittest suite passed 96 tests after the changes. The read-only
  source audit passed for 61 evidence references across 30 patterns.
- Actual vulnerable and adjacent fixed upstream releases were probed across
  ten version cases. A frozen 20-case holdout passed 10 risk and 10 safe cases.
- Focused changes in isolated vulnerable installations passed the same 20
  boundary cases. Django, Cookiecutter, and CPython used adjacent fixed-release
  source files; BentoML used the observed main-service HTTP guard. This does
  not establish an agent's patch success, exploitability, or full integration.
- The loaded package version and source path were asserted; source and
  interpreter hashes are recorded in the result files. Promotion remains false.
- The remaining uncovered guidance branches reject malformed bundled schema,
  manifests, source pairs, or unsupported basis labels. The supported candidate
  path, unknown ID, stale pin, source mismatch, and anchor failures were tested.

## Review Decisions

- fixed -> Mercurial target fact named repository input instead of checkout
  branch/revision -> source patch lines 29-39 and targeted test pass.
- fixed -> one broad patch range did not support every card claim -> per-item
  source, inference, and process references are validated against pinned files.
- fixed -> IPvFuture preservation was absent from the boundary example ->
  current urllib.parse positive case for v6a.ip passes.
- fixed -> Django post-sanitization filename validation was absent -> guidance
  and illustrative tests now include empty and dot-dot outcomes; patch lines
  203-207 and 288-295 support the correction.
- fixed -> independent reviewer found missing loaded-source identity checks
  and broad exception catches in the probes; both were narrowed and rerun.
- pending -> the project owner has selected self-review but has not recorded
  card-level decisions. No human approval or agent effectiveness claim exists.
