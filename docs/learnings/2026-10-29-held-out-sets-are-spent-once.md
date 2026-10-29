---
title: A held-out set is honest only for its first scan
scope: detection evaluation
confidence: high
seen: 1
tags: [evaluation, detection, held-out]
type: decision
---

**Context:** Detection was measured on public projects never used to write the
rules. Each first scan exposed misses (2/6, 8/10 with one false positive, 2/5),
and each miss was then fixed.

**Options:** Report the post-fix 21/21 as the result, or report each set's first
scan and label post-fix numbers as development results.

**Decision:** Fix expected locations by reading code before scanning; report the
first scan of each set as the held-out figure; treat a set as a development set
once it shaped the rule; use a fresh set for the next honest measurement.

**Why:** Fixing the rule on a set and then re-measuring on it only shows the set
was memorised. Counting the expectation the scanner exceeded (meson wrap.py:808)
also keeps the expected list honest.
