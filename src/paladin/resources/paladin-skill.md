---
name: paladin
description: Check this project for known CVE patterns and vulnerable pinned dependencies with Paladin's MCP tools, then explain each finding and how to fix it. Use when the user asks to run Paladin, scan or check the project for CVEs, or audit dependencies.
---

# Paladin project check

Use the `paladin` MCP server. If its tools are not available, tell the user to run
`paladin mcp install` for this project (and approve or trust it), then stop.

1. Call `check_project` (no arguments). It checks every Python file of the project
   statically; `checked_files` counts them, and only files with findings or problems
   (unreadable, linked, too large, parse failures) are listed. Each rule's title and
   fix are under `rules`, keyed by `rule_id`.
2. Call `check_dependencies` (no arguments) for pinned versions in known CVE ranges.
3. When a blocking finding needs more than its fix line, call
   `search_prevention_patterns` with the CVE id and the rule title as `intent`; use the
   card whose `cve_id` matches (its `cause`, `preconditions` and `prevention`). If search
   is unavailable, the fix line under `rules` is enough.
   If the user named files or folders, limit the report to those.

Report, most severe first:

- Blocking findings: file:line, CVE and severity, what is wrong, the fix direction.
- Review findings: grouped by rule, one line each; say they are pattern matches to
  confirm in context, not confirmed vulnerabilities.
- Dependencies: package, pinned version, CVE, first fixed version.
- Coverage: files checked, anything partial or skipped, and that a clean result is
  not a security verdict. The dependency check knows only the CVEs in Paladin's card
  pack; say it is not a full audit of every advisory for those packages.

Do not edit code during the check. Offer to fix the blocking findings afterwards;
fix only what the user approves.
