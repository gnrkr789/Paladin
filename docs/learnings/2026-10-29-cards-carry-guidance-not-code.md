---
title: Prevention cards carry the problem and fix direction, not fixed code
scope: knowledge expansion, card drafting
confidence: high
seen: 1
tags: [design, cost, cards]
type: decision
---

**Context:** The first CVE expansion plan collected upstream patch bytes and had
an LLM draft cards from the diffs.

**Options:** Store and replay upstream fixes, or describe the problem and the fix
direction and let the user's agent implement it.

**Decision:** Cards state cause, preconditions, prevention direction and limits.
Fix commits are reference URLs only; no patch code is collected for new cards.
Drafting input is the short advisory text.

**Why:** The user's agent writes its own implementation once it knows the
problem, so carrying fixed code adds cost (large diffs as model input, storage,
licensing) without benefit.
