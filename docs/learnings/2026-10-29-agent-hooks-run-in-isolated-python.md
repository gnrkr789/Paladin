---
title: Agent hook commands must run Python in isolated mode
scope: agent hooks, MCP workers
confidence: high
seen: 1
tags: [security, hooks, python]
type: lesson
---

**Context:** The Claude Code hook ran `python -m paladin.cli` with the hooked
project as its working directory.

**Observation:** `python -m` puts the working directory first on `sys.path`, so a
repository containing `paladin/cli.py` or `json.py` ran its own code on every
agent edit (reproduced: it printed PLANTED). `python -I` and the console script
both load the installed package.

**Decision:** Hook commands and the MCP worker use `-I`; the hook refuses to run
when Paladin was imported from the workspace; absolute paths are written with
forward slashes and no quotes so the command works in bash, PowerShell and cmd.

**Why:** Hooks run on untrusted repositories with no permission prompt.
