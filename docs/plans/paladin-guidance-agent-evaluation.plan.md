# Plan: Candidate guidance agent patch evaluation

Status: review
Done: E3, E4, E5, E6
Size: Medium

## Summary

Evaluate whether a coding agent receiving one pinned Paladin candidate card can
repair source copied from five vulnerable upstream releases. Keep every agent
edit in an isolated task directory and score it with private boundary cases.
Do not alter the frozen M5 evaluation or promote candidate guidance.

## Behavior

- E1 frozen tasks: Given five vulnerable upstream versions and candidate cards,
  when the evaluation starts, then source identities, prompts, model settings,
  private cases, and scoring rules are fixed before any agent edit.
- E2 actual edits: Given an isolated vulnerable source copy, when the coding
  agent receives the task with or without Paladin guidance, then its trace and
  changed files are preserved without modifying authoritative source or tests.
- E3 independent score: Given each resulting patch, when private risk and safe
  cases run on an isolated vulnerable installation, then loaded source identity,
  risk rejection, and normal behavior are recorded per case; missing results
  remain incomplete.
- E4 bounded report: Given all attempts, when results are summarized, then
  successful repair, failures, and incompletes are separate; five correlated
  families do not support a broad or causal effectiveness claim.
- E5 replay identity: Given the preserved worker patches, when a new replay is
  frozen, then scorer code, package trees, patch snapshots, cases, and runtime
  identities are recorded and verified before any new probe execution.
- E6 replay diagnostics: Given a frozen replay, when any probe exits or raises,
  then its exact command, exit code, stdout, stderr, loaded source and score are
  saved in a separate artifact without changing the original run records.

## Tasks

1. Freeze five source subsets, card hashes, private cases, host settings, and
   a no-guidance comparator prompt before running the agent -> E1.
2. Run isolated Codex CLI attempts and preserve JSONL, stderr, prompts,
   before/after hashes, and changed file list -> E2. CLI execution was blocked;
   a separately frozen collaboration-worker protocol supplied actual edits but
   did not preserve local worker tool traces.
3. Apply each agent patch to a fresh vulnerable installation and run the
   independent boundary oracle; test baseline and fixed controls -> E3.
4. Review traces, score exact outcomes, run project checks, and write a concise
   limitation-aware report -> E4.
5. Freeze a retrospective replay with full input manifests and test its
   integrity verifier -> E5.
6. Re-run the preserved patches under that replay, capture failures, and
   compare scores without overwriting primary evidence -> E6.

## Validation

- Private cases pass on fixed releases and fail as expected on vulnerable
  releases before agent work.
- All 10 worker attempts have an outcome and before/after source hashes; local
  worker tool traces are unavailable.
- Source path and vulnerable version are asserted in oracle runs.
- `.venv/Scripts/python.exe -B -m unittest discover -s tests -q`.
- Replay refuses an altered manifest member and preserves failing subprocess
  diagnostics; all 10 replay results bind to archived patch hashes.

## Risks

- One attempt per family and arm yields only descriptive evidence; no general
  improvement rate or model-independent effect can be inferred.
- Full-package integration and exploit execution are outside this boundary
  evaluation. Record any additional source imports or unsupported edit surface.
- Upstream changes between adjacent releases may include unrelated behavior;
  the fixed release is a control, not the agent's patch.

## Verified Facts

- The five isolated vulnerable and fixed packages already exist under
  `.validation-cache`; previous release and patched-source boundary probes
  passed their separate 20-case evaluation.
- The prior M5 host used codex-cli 0.163.0 with gpt-6-sol medium. M5 is frozen
  and remains inconclusive; its tasks and result files must not be rewritten.
- The worker primary summary is A: four success, one incomplete; C: four
  success, one failed. Both BentoML repairs pass four ASGI post hoc boundary
  cases, but this separate check does not change the primary scores.
- The project test suite passed 98 tests; source audit passed 30 patterns and
  61 evidence references. Post hoc source hashes match scored repair artifacts.
- The v5 retrospective replay froze 10 oracle trees, the compatibility tree,
  three Python runtime trees, three project code trees, and the preserved
  primary artifacts before its own 10 executions. All 10 status labels matched
  primary results; raw stdout/stderr hashes matched their run records.
- The final project suite passed 107 tests; the source audit remained PASS.

## Review Decisions

- fixed -> post hoc runner did not enforce scored repair identity -> added
  after-hash and source snapshot verification; `POSTHOC_IDENTITY_OK`.
- deferred -> scorer and complete upstream installation were not frozen ->
  current source subsets and 10 edited oracle files match recorded hashes, but
  old frozen protocol and primary scores must not be rewritten.
- deferred -> failed primary oracle stderr was discarded -> A BentoML original
  traceback is unavailable; report limits diagnosis to source and post hoc
  behavior rather than inventing the missing trace.
- deferred -> worker tool traces are absent -> E2 trace-preservation condition
  is unmet; no claim that private cases were proven unseen.
- deferred -> probe subprocesses inherit the host environment -> report
  describes source-directory separation without security isolation.
- approved follow-up -> user requested autonomous evidence reinforcement;
  E5 and E6 add a separately frozen retrospective replay, not a primary rescore.
- fixed -> prior freeze and project import neighbors were not checked before
  every replay attempt -> v5 authenticates the freeze and complete project
  code trees per attempt; 10 replay statuses match primary artifacts.
- fixed -> launch errors, malformed output, ancestor reparse points, runtime
  code, and stale evaluator bytecode were weak boundaries -> v5 records launch
  failures, validates JSON, rejects reparse paths, hashes runtime trees, and
  uses an empty redirected bytecode cache; 107 project tests passed.
- deferred -> the original pre-agent freeze and worker tool traces cannot be
  reconstructed by a retrospective replay; E1 and E2 remain partly unmet.
- deferred -> same-user probe execution is not an OS sandbox and cannot provide
  adversarial tamper resistance or hidden-case secrecy; report states this.
