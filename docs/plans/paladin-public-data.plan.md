# Plan: Apache-2.0 release preparation with redistributable data

Status: review
Done: P1, P2, P3

## Decision (user, 2026-10-29)

Paladin code and authored knowledge are licensed under Apache-2.0. The base data
used by the experiments and the collected CVE evidence are published so users
start from a common base and extend it locally; there is no shared hosted
service. Web page snapshots without a clear redistribution license are not
published; users fetch them from the origin and Paladin verifies their hashes.
Switching the repository to public is decided later.

## Behavior

| ID | Given | When | Then |
|---|---|---|---|
| P1 | the repository | a user reads LICENSE, NOTICE and data/THIRD_PARTY.md | Paladin is Apache-2.0 and every committed third-party file maps to its license with the required notice text |
| P2 | the five unlicensed web snapshots | the tree is published | they are not in the tree; data/external-references.json keeps their path, URL and sha256 |
| P3 | a fresh checkout without them | the M0 validator and the unit suite run | the five references are listed in data/external-references.json and are skipped, not errors; everything else is validated as before |

Plan change (2026-10-29): a hash-verified fetch command was dropped. The live
pages already differ from the recorded bytes (checked: both a Django weblog page
and the GitHub advisory page hash differently today), so a verified re-fetch can
never succeed, and no runtime feature reads these files.

## Tasks

- T1 (P1): LICENSE (Apache-2.0 text), NOTICE, data/THIRD_PARTY.md and licenses/ texts.
- T2 (P2): remove the five files from the tree; list them in data/external-references.json; ignore their paths.
- T3 (P3): validator accepts listed external references; fresh-checkout test run with the files absent.
