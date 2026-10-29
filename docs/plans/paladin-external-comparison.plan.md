# Plan: External project repair comparison

Status: review
Done: X1, X2, X3, X4

## Approved scope

Run a prospective comparison on fresh source checkouts of real public projects.
Use Cookiecutter 2.1.0 and Django 3.2.13: known vulnerable controls, not an
arbitrary-project vulnerability prevalence sample. Compare generic repair
instructions, existing summary guidance and complete patch context using the
same source and private risk/safe checks. Freeze inputs before agent edits.
Preserve failures, source hashes, agent reports and raw evaluator output.

## Behavior

- X1: Sources, prompts, cases and evaluators are fixed before repair attempts.
- X2: Agents edit distinct full-project copies; scoring uses preserved patches
  with runtime checks against the real imported project code.
- X3: Compare risk rejection and safe compatibility, and diagnose failures.
- X4: If benefit is absent, improve the concrete diagnosed content/measurement
  defect and verify it without claiming an unobserved accuracy gain.

## Limits

Known vulnerable projects measure repair on selected vulnerabilities. Paladin
check_changes is unsupported; retrieval is not automatic source scanning.
One attempt per arm/project is descriptive. Agents share a filesystem, so
private-case nonexposure and OS isolation are not independently guaranteed.
Full project source manifests and final worker reports are preserved; local
complete worker tool traces may be unavailable.

## Results

- Fresh upstream Git commits and full project copies are recorded in freeze.json.
- Primary A/B/C: Django 18/20, 20/20, 20/20; Cookiecutter strict argv fidelity
  6/12 for each. This latter score is not a containment-failure count.
- Explicit compatibility constraints fixed the diagnosed defect in D:
  Django 20/20; Cookiecutter 12/12, real offline Hg checkout 2/2 versus 1/2
  in A/B/C. D is diagnostic, not independent causal confirmation.
- Manual code-intent semantic retrieval ranked the corresponding CVE first
  for both projects. Source scanning remains explicitly unsupported.
- Paladin suite passed 112 tests; source audit PASS, 30 patterns/61 references.

## Review decisions

- fixed -> primary Cookiecutter metric conflated strict argv fidelity and
  security containment -> preserved primary raw scores and added separately
  labeled containment plus real offline Hg compatibility checks.
- fixed -> mocked process checks ignored shell/executable kwargs -> separate
  subprocess contract records and validates both flags.
- fixed -> supplementary tested sources were not hash-bound -> repeated core
  compatibility checks with source manifests before and after execution.
- fixed -> follow-up scorer lacked runtime/runner checks -> runner sealed
  after tasks before scoring, primary runtime manifest checked; timing disclosed.
- deferred -> older upstream-suite results lack execution-time source manifests
  -> retained with weaker-provenance label; no retroactive sealing claim.
- deferred -> fixed-control identities were captured after control execution
  -> marked post hoc. No evidence of drift was observed.
- deferred -> limited projects, shared filesystem, absent complete worker traces
  and OS sandbox -> no broad effectiveness or automatic-detection claim.
