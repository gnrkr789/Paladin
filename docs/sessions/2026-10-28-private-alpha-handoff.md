# Handoff: private alpha complete for review (2026-10-28)

Supersedes `2026-10-27-private-alpha-handoff.md` (kept for history).
Plan: `docs/plans/paladin-private-alpha.plan.md`, now `Status: review`
(GATE 2: the user decides on deferred findings). Final report:
`docs/evidence/private-alpha/final-report.md`. Nothing committed, pushed,
uploaded or deployed. Conversation in Korean; project files English ASCII.

## State

- All seven steps of the previous handoff are done; every gate in the final
  report is PASS (boundary 7/7, external evaluation, sources unchanged,
  176 unit tests, two fresh-context reviews with 0 CRITICAL/HIGH, wheel/sdist
  clean install with real verification, promotion, listing and reuse).
- Final evaluation: `docs/evidence/private-alpha/eval-v4/run-20261028T022306Z/`.
  Packaging: `docs/evidence/private-alpha/package/report.json` (PASS).
- `.paladin/runtime.json` in the checkout points at image
  `sha256:38fd7788...`; workspace `.validation-cache/private-alpha-eval/ws-20261028T022306Z`
  holds the two promoted v4 cases. The checkout's own `.paladin/cases.sqlite3`
  still holds only the retained legacy v2 record.

## Changes since the 2026-10-27 handoff

- Review fixes: index-aware shared-fs cwd; `validate_output` extracted and
  tested; CLI reason codes for host trace/payload errors; removed
  `src/paladin/case_probe.py` (unsandboxed host path; copies remain in
  `docs/evidence/cve-case-loop-final/`); repair dispatch by rule id; rename,
  renameat, renameat2, link, linkat traced (`path_alias_created`, formerly
  `symlink_created`); apt versions logged at build.
- Launcher runs as `python -I -B` (bytecode writes in `/work` were renames).
- Host per-case timeout 120 s, observer PID wait 60 s; container removal
  retried; up to 3 attempts in fresh containers for Docker CLI timeouts only,
  counted as `infrastructure_retries`.
- Two developer-checkout-dependent tests (`test_actionable_guidance`,
  `test_patch_context`) now use a temporary workspace with a copy of `data/`.
- New `scripts/run_private_alpha_eval.py`; `scripts/build_private_alpha.py`
  now also checks runtime policy, real verification, listing, reuse and source
  hashes from the installed CLI (`--skip-runtime` to omit; needs Docker).
- Docs updated: `docs/case-loop.md`, README case-loop paragraph,
  `docs/private-alpha-install.md`.

## Commands

```
uv --cache-dir .cache/uv run --frozen --no-sync python -m unittest discover -s tests
.venv/Scripts/python.exe -I scripts/run_private_alpha_eval.py
uv --cache-dir .cache/uv run --frozen --no-sync python scripts/build_private_alpha.py
```

Docker Desktop must be running (it was stopped after a reboot once). The
evaluation takes about 20 minutes, packaging about 15.

## Open decisions for the user

1. Security M1 (deferred): in-process hg hooks plus target-writable branch file
   can fake `safe_*`. Options: accept as documented limit, or have the root
   observer re-verify the checkout from a copy with repo config ignored and
   disqualify clones whose `.hg/hgrc` differs from the fixture clone output.
2. Pin apt package versions (currently only logged).
3. Whether to commit; nothing has been committed.
4. Plan status: set `done` after the user settles the review items.
