# Paladin M5 comparative evaluation

Status: evaluated; primary comparison inconclusive; stopped at M5
Implementation and evaluation requested 2026-10-26.
The scored protocol was frozen and the 120-attempt schedule was recorded.
See [M5 result](../evidence/m5-report.md) for the primary and separate post hoc
results. No scored task was rerun.
Parent: [CVE prevention plan](paladin-cve-prevention.plan.md).
Prior checkpoint: [M4 report](../evidence/m4-report.md).

## Scope and decision

Measure whether advisory Paladin retrieval changes the rate of vulnerable
implementations in actual Codex CLI tasks while retaining requested behavior.
The existing M4 run proves one prompted workflow only. M5 must use a frozen
task set and identical host conditions across comparison arms.

The current `check_changes` capability returns `unsupported` with
`rules_not_validated` and `inspection_performed=false`. Condition D (retrieval
plus checks) is ineligible until independently validated rules, applicability,
and inspection receipts exist. Do not label advisory self-review as D. Host
enforcement remains a separate future condition.

## Freeze before host runs

1. Define 20 weakness-development tasks and 20 safe/protected tasks in English
   ASCII. Each task has a fixed starting tree, user request, completion tests,
   vulnerability-condition tests, and an expected behavior record. The current
   synthetic catalog has four behavior families, five named contexts per family,
   and two starting states per context. These are 40 task instances but only
   four broad code structures; report family-level outcomes and do not treat
   the 40 instances as independent evidence of general effectiveness.
2. Split tasks by project and pattern family. Exclude derivatives of source
   examples, CVE patches, or prompts in Paladin's knowledge pack from the held
   out set. Preserve rejected candidates and reasons without retuning them into
   a new unseen holdout.
3. Pin task-set and test hashes, pack/model/index identity, Codex CLI and model
   settings, prompts, tool availability, permission mode, time limits, hardware,
   and run order. Record available credits and an explicit run budget before
   starting. Do not mutate the authoritative pack during evaluation.
4. Pilot only the harness with non-scored fixtures. Confirm real file edits,
   test execution, raw host events, timeout cleanup, and failure capture.
   Freeze the scored protocol after this pilot and before any scored run.
   The first sandboxed pilot failed to find the existing Codex home. An
   elevated invocation reached the host but its effective read-only policy
   rejected the edit and test; exit code 0 did not meet this gate. Preserve
   both attempts.

## Comparison

Use the same 40 tasks and one run per task and eligible arm, for at most 120
scored Codex runs. The user selected this run budget on 2026-10-26. This
supports a bounded comparison with greater uncertainty than the original
three-run design.

| Arm | Instructions and tools | Eligibility |
|---|---|---|
| A | Existing task instructions | After protocol freeze |
| B | Same task plus generic security instructions | After protocol freeze |
| C | Same task plus Paladin advisory retrieval | After protocol freeze |
| D | C plus validated deterministic change inspection | Deferred until the inspection gate is met |

Run order should be balanced across eligible arms and recorded before execution.
Use fresh task copies and isolated host state for every run. Preserve every raw
attempt, including refusals, partial edits, timeouts, tool failures, and policy
rejections. A zero host exit code is not evidence of an edit or a passing test.

## Scoring and reporting

Score functionality and vulnerability conditions using independent tests,
static evidence, and human review of ambiguous outcomes. The generating model's
statement is not a score. Rejecting a request or removing requested behavior
does not count as prevention success. Record whether the agent called, received,
and used Paladin evidence separately from the final code outcome.

Report raw counts, denominators, absolute differences, uncertainty intervals,
and family-level results. Relative recurrence reduction is undefined when the
baseline recurrence count is zero. Report safe-task false blocking, retained
functionality, refusals, incomplete attempts, evidence provenance, call and
consumption rates, cold/warm latency, memory, disk, and token overhead. Mark D
and enforcement as not evaluated until their gates are met.

The parent plan's provisional product gates are at least 30% relative recurrence
reduction, at most 5% false blocking of safe tasks, 100% provenance for active
patterns or blocking findings, and retained functionality. With only 20 safe
tasks, report run-level and task-level denominators so the 5% gate is interpreted
honestly. Do not turn a missed gate into repeated tuning of the frozen set.

## Stop conditions

- Stop before scored runs if leakage, missing baseline tests, unpinned settings,
  incomplete host evidence, or an uncontrolled cost/time budget is found.
- Stop and report an attempted run as incomplete if host permissions prevent
  editing or testing; do not silently substitute a parent-applied fix.
- After one fixed evaluation, permit at most one separately approved bounded
  diagnosis/fix/re-evaluation. Keep the original runs and labels unchanged.
- Do not claim validated vulnerability detection, approval, blocking, desktop
  integration, or general effectiveness from advisory retrieval results.

The fixed evaluation reached this stop point. Primary C scoring completed only
5/40 attempts under the frozen evidence-use rule, leaving the comparison
inconclusive. Further diagnosis or evaluation requires a separate decision.

## Approval gate

Before scored execution, freeze and verify the task selection method, leakage
exclusions, test oracles, exact prompts, host permission mode, run budget, and
reporting denominators. If any item cannot be established, stop and report the
incomplete evaluation rather than changing the benchmark during execution.
