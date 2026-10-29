---
title: A history rewrite and force push does not remove objects from GitHub
scope: repository publishing
confidence: high
seen: 1
tags: [git, github, licensing, publishing]
type: lesson
---

**Context:** Five web snapshots without a redistribution license had to leave the
repository before it could go public. History was rewritten with filter-branch and
force-pushed.

**Observation:** After the force push, GitHub still served the old commit and the
removed blob by SHA (`gh api repos/.../commits/<old sha>` and `git/blobs/<sha>`).
Squashing would only add more unreachable commits. GitHub documents that only a
Support-run garbage collection, or deleting and recreating the repository, removes
them.

**Decision:** The user recreated the repository; the clean history was pushed and
both SHAs then returned "not found".

**Why:** Verify removal by querying the old SHAs on the server, not by inspecting
the local history.
