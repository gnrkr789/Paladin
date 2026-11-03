# Plan: Check candidate cards against their upstream fix

Status: done
Done: P1, P2, P3, P4, P5, P6, P7

## Summary

494 of 524 cards are `candidate`: drafted from advisory text only. Each is now
compared with the upstream fix commit or pull request its advisory links (490
cards have one). A model reads the card and the diff and says whether the card's
cause and prevention match what the fix changes. Matching cards become
`patch_checked`; a card that does not match is rewritten from the diff, without
code, and checked again.

## Decisions (user, 2026-11-03)

- The diff is read during the check only. The repository keeps the diff URL,
  its sha256 and size, never the patch text (design rule of 2026-10-29).
- A mismatched card is rewritten to match the fix and re-checked; it is
  promoted only if the re-check agrees.
- Pilot of 20 cards first, with headless Claude Code (Sonnet 5.5), to measure
  cost and verdicts before the remaining cards.

## Behavior

| ID | Given | When | Then |
|---|---|---|---|
| P1 | a GitHub commit or pull request URL | the diff URL is built | only github.com commit and pull URLs are accepted; other URLs are skipped |
| P2 | a large diff | it is prepared for the model | documentation, changelog and lock files are dropped, source files come before tests, and the text is cut at a fixed budget, marked as truncated |
| P3 | a model answer | it is validated | verdict is aligned, misaligned or unrelated; prose fields are English ASCII without code; no added line of the diff is copied |
| P4 | verdict aligned | the review is recorded | the card is promoted to patch_checked with the observation and the diff hashes |
| P5 | verdict misaligned with a revision | the revision is checked against the same diff | aligned on re-check promotes the revised card; otherwise it stays candidate with the reasons |
| P6 | verdict unrelated, no usable diff, or a failed fetch | the review is recorded | the card stays candidate with the reason |
| P7 | the change hook | any edit | unchanged: no model, network or patch data (existing guard test) |

## Pilot (2026-11-03, 20 cards, seed 20261105)

- 18 patch_checked: 9 aligned as drafted, 9 misaligned, rewritten from the diff,
  and aligned on re-check.
- 1 unrelated (CVE-2020-1735: all three linked commits only edit a changelog
  fragment), 1 no diff (CVE-2026-42266 links a release tag only).
- Cost $3.00 for 28 calls, about $0.15 per card; about $71 for the other 474.
- Rewrites read as patch-grounded: for example CVE-2023-24769 moved from output
  encoding to a URL scheme allowlist, which is what the fix does.

## Results (2026-11-03, all 494 candidates)

- 471 patch_checked: 264 aligned as drafted, 207 rewritten from the diff and
  aligned on re-check. Every rewrite passed its re-check, so the re-check by the
  same model adds little; a person has not reviewed these cards.
- 23 stay candidate: 15 unrelated (the linked commits do not show the fix),
  7 without a GitHub commit or pull diff, 1 answer rejected for copying a diff line.
- 26 diffs were cut at the 60,000-character budget; 4 cards had a fetch failure
  on one of their links.
- Cost $56.28 in total (pilot $3.00, rest $53.29).
- Retrieval after the rebuild (all sets are now development sets), hit@5 / MRR,
  before -> after: v1 0.950 / 0.900 -> 0.950 / 0.867; v2 0.754 / 0.641 ->
  0.826 / 0.715; v3 0.781 / 0.603 -> 0.875 / 0.643; v4 0.831 / 0.697 ->
  0.881 / 0.710; v5 0.873 / 0.736 -> 0.909 / 0.746.

## Second-model audit (2026-11-03)

Codex gpt-6-astra audited 30 of the 207 rewritten cards (seed 20261106,
scripts/audit_reviews.py, records in data/cve-expansion/patch-review-audit/). It saw
the original card, the rewrite and the same diffs (re-fetched, sha256 checked),
but not the advisory text.

- Rewrite matches the fix: 10 yes, 20 partly, 0 no. Better than the original: 30 of 30.
- Partly means the main weakness and fix direction are right, but a side claim is
  wrong or not shown by the diff. Real errors include executor-specific command
  prefixes stated as one rule (CVE-2020-11981) and URL anchoring advice the test
  contradicts (CVE-2018-14574). Many other flags are version ranges or attack
  preconditions that come from the advisory, which the auditor did not see.

## Correction and Fable audit (2026-11-03)

- User decision: correct all 207 rewritten cards, have Fable review them, and
  commit and push if the result is reasonable.
- Codex gpt-6-astra corrected every rewritten card with the advisory text and the
  same diffs in view (scripts/audit_reviews.py correct): keep supported claims, fix
  contradicted ones, move unsupported version ranges, prerequisites and scope to
  limitations. All 207 passed the text rules; 6.3 edits per card on average.
  The pack uses the corrected text (field corrected in each review record).
- 9 corrections made the search passage longer than the e5 encoder's 512 tokens
  (the export refused them). The correction step now caps title, cause,
  preconditions and prevention at 1,800 characters, and those 9 were corrected again.
- Fable (claude-fable-5-1) audited a fresh sample of 30 corrected cards (seed
  20261107) with the advisory text and diffs: 29 match the fix, 1 partly (an omitted
  secondary change in CVE-2026-73415), 0 wrong; all 30 better than the draft. Cost
  $6.45. Before correction, Codex had judged 10 of 30 exact; the auditor and its
  inputs differ, so the two samples are not a strict comparison.
- Retrieval on the development sets after correction, hit@5 / MRR: v1 0.950 / 0.900;
  v2 0.826 / 0.677; v3 0.828 / 0.657; v4 0.847 / 0.685; v5 0.927 / 0.754. All stay
  above the hybrid before the patch review and above the 0.8 / 0.6 gate; v3 and v4
  are lower than right after the review (0.875, 0.881).

## Risks

- Fix links can point at a release, a merge or an unrelated commit: verdict
  unrelated keeps the card a candidate.
- Truncated diffs can hide the fix: the record says truncated, and the model may
  answer unrelated.
- A model check is not a human review; the status says patch_checked, not
  verified by a person.
