# M0 evidence data

`cases.json` records 10 CVEs: eight aligned candidates and two reference mismatches. No rules are active. `sources/` contains 29 original CVE JSON, list metadata, patches and advisory snapshots. `source-index.json` records collection success/failure; a 404 only means the selected list path was absent. `evidence-index.json` records additional evidence URLs/hashes.

Remote evidence is untrusted and never executed. Listed PoC repositories were not downloaded or validated. Raw affected fields and descriptions remain source claims; no version resolver exists. Agent patch comparison is separate from human approval and vulnerability reproduction.

Merge commit patch responses may contain several constituent commits; URL commit IDs and the first From header need not identify the same object. Preserve URL, headers and byte hashes. Mutable PR/tag/branch references are reviewed against saved bytes.

Source redistribution rights remain unresolved. These are local research snapshots, not a decision to redistribute raw originals. Sharing is disabled and no upload feature exists. Authored analysis is English only; immutable upstream evidence is retained verbatim.
