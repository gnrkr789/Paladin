# Plan: One Paladin home per user, checks per project

Status: done
Done: H1, H2, H3, H4, H5

## Summary

Search state (Milvus configuration, the 487 MB encoder, the pattern index, verified
cases and evidence snapshots) lives in `<workspace>/.paladin`, so every project needs
its own setup, and the MCP server can serve either the index or the project, not
both. Milvus already binds the fixed port 19530, so there is one per machine anyway.

The search state moves to a per-user Paladin home. Project tools (check_changes,
check_dependencies, scan_cve_candidates) keep reading the project workspace. One
`paladin setup` per user, then one hook and MCP entry per project.

## Behavior

| ID | Given | When | Then |
|---|---|---|---|
| H1 | PALADIN_HOME is set | the home is resolved | it is that folder |
| H2 | no PALADIN_HOME | the home is resolved | it is %USERPROFILE%/.paladin on Windows, $XDG_DATA_HOME/paladin or ~/.local/share/paladin elsewhere |
| H3 | setup, doctor, model, patterns and search (not cases) | they run without --home | they use the resolved home; --home picks another; --workspace stays accepted as the old spelling |
| H4 | `paladin mcp --workspace P` | an agent calls search, evidence, guidance or status | they read the home; check_changes, check_dependencies and scan_cve_candidates read P |
| H5 | the change hook and `paladin deps check` | they run | unchanged: workspace only, no home needed |

## Decisions

- User, 2026-11-03: build the shared structure (after the agent sessions showed the
  MCP checks could not read the task folder).
- No automatic migration: a home is set up with `paladin setup --home`; an existing
  checkout state can serve as the home by pointing PALADIN_HOME at it.

## Results (2026-11-03)

- `paladin mcp --workspace <project> --home <home>`: search answered from the
  home's index while check_changes and check_dependencies read the project
  (C:/Users/user/Desktop/personal/paladin-codex-e2e).
- Evidence, guidance and verified cases stay with the workspace: their source
  snapshots live in the Paladin checkout's data folder, and `paladin cases` records
  there, so get_prevention_guidance still finds them. get_knowledge_status takes index
  readiness from the home and counts evidence snapshots in the workspace. Moving
  these into the home is open (code review, 2026-11-03).
- Found while testing: check_changes returned status "findings", which the MCP
  output schema does not allow, so clients rejected every result that had a
  finding. It now returns status "complete" with outcome "findings", like
  check_dependencies. The earlier test asserted the invalid status and was fixed.
- Moved this machine to the default home (user decision, 2026-11-03): stopped the
  checkout's Milvus (containers and data kept), ran setup in the new home, copied
  the encoder instead of downloading it, indexed from the packaged vectors. Search
  and the v5 development set give the same numbers as before (0.927 / 0.754).
- %LOCALAPPDATA% was the first Windows default and failed on this machine: a process
  started from an MSIX-packaged host (the Claude desktop app here; the Codex desktop
  app is packaged too) writes to a private, redirected copy of it, which Paladin's
  path check rejected and which Docker would not see. The Windows default is now
  %USERPROFILE%/.paladin. The Milvus project that first attempt started was removed.
- eval/run_m2.py, eval/m2_relabel.py and scripts/run_agent_e2e.py now use the home
  for search; run_agent_e2e starts MCP on the task folder. Two MCP tests that relied
  on an empty machine home now pass their own empty --home.
