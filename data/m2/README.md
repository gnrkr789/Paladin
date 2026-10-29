# M2 source acquisition

The advisory pack reuses eight aligned M0 cases and adds 22 cases from Django security history and urllib3 CVE references. This directory contains 44 added CVE/patch snapshots and their source index. The two M0 reference mismatches remain excluded.

Source URLs and hashes are in `source-index.json`. Snapshots are untrusted immutable evidence, never executed. CVE-2021-3281 retains the historical prefix-check limitation and also links CVE-2025-59682's component-aware containment patch.

The 30 English cards and 60 risk/safe specifications are in `src/paladin/resources/prevention-pack.json`. Fixtures are `specification_only`, not executed regression tests. `source_observed` records Codex source comparison, not human approval. `version_applicability.source_affected` preserves source values verbatim; affected versions are not normalized or resolved. Human approvals, blocking rules, reproduction and sharing remain absent. Raw source redistribution rights require separate review.
