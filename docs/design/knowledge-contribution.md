# Cross-user knowledge analysis and prevention feedback

Status: design proposal; no network sharing implementation.

Different users accumulate different local databases as stacks and observations vary. Comparing shareable evidence could reveal common causes, missing guards and unmodeled variants. Reviewed rules could then return to local databases and prevent recurrence. This is a hypothesis, not proven prediction of unpublished vulnerabilities.

Proposed cycle: local observations -> selected shareable contributions -> deduplication and cross-analysis -> reviewed/tested rules -> versioned local data packs.

## Proposed contribution contract

| Category | Fields |
|---|---|
| Identity | contribution_id, schema_version, pattern_id/revision, content_hash |
| Provenance | public URL, commit/blob/hash, CVE/CWE, location, acquisition time |
| Applicability | source version claims, stack, privilege, input and call prerequisites |
| Prevention | cause, missing guard, correction, legitimate exceptions |
| Verification | candidate/reviewed/rule_tested/reproduced, evidence and verification logs |
| Sharing rights | selected scope, consent, per-source license, retention/withdrawal |
| Lineage | derived_from, upstream evidence IDs, duplicate group, correction history |

Use English authored fields and supported inputs. Separate public CVE evidence from private-project observations. Export selected reviewed records, not whole raw DBs. Project code, local paths and secrets are excluded by default. Hashes and pseudonyms alone do not guarantee anonymity.

## Processing and evaluation

1. Check schema, integrity, consent, provenance and reuse rights.
2. Deduplicate by CVE, upstream patch, content and lineage.
3. Compare stacks, guards and safe counterexamples; similarity alone cannot merge rules.
4. Preserve conflicts and keep new rules as candidates; repeated copies are not independent verification.
5. Review and test vulnerable/safe behavior before publishing a pinned data pack.
6. Track withdrawals/corrections through derived rules and local updates.

The M0 mismatched CVE/patch references are concrete evidence against blind merging. Future work must distinguish malicious contributions, correlated participants, contribution withdrawal and independent retention of public evidence.

Evaluate new rules on tasks first appearing after aggregation, against the same tasks with only individual DB knowledge. Count recurrence and retained functionality, not contribution counts. There is currently no uploader, aggregation service or distribution server; all sharing flags remain false.
