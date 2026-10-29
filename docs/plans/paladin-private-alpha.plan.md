# Plan: Local private alpha readiness

Status: review
Done: T1, T2, T3, T4, T5, T6, T7 (real evaluation and clean install PASS; see docs/evidence/private-alpha/final-report.md)
Handoff: docs/sessions/2026-10-28-private-alpha-handoff.md

## Approved objective

Prepare a local private-alpha distribution with a trustworthy verification
boundary, structural source-variant support, external validation and clean
installation evidence. External projects are validation subjects, not supported
customer integrations by default. No publication, release upload or deployment
to other users is authorized by this plan.

## Behavior

- A1: Target code executes only in a bounded, network-disabled, read-only-host
  container. A separate privileged observer records real process execution;
  target stdout/JSON cannot create a passing observation.
- A2: Supported source structures can be verified without exact before-source
  fingerprints. Unsupported adapters fail closed. Original source stays intact.
- A3: Only source-bound successful observed before/after cases are promoted.
  Host-authenticated evidence is rechecked on reuse; old unauthenticated records
  remain retained and excluded.
- A4: Evaluate adversarial spoofing, filesystem/network/resource boundaries,
  positive/negative/fixed controls and independently authored external projects.
  Freeze input/code/image identities and report limitations and failures.
- A5: Produce a versioned local alpha wheel and source archive; install from
  those artifacts in a clean environment outside the checkout and demonstrate
  CLI/MCP scan, verification policy and case persistence.

## Gates

No arbitrary host execution fallback. No automatic promotion from target claims.
No alpha-ready claim until real isolation checks, security regressions, existing
suite and fresh-install artifact checks pass. The alpha remains scoped to
documented CVE rules/adapters and English ASCII inputs. Broader detection or
production safety is not implied by these checks.

## Resumed tasks (2026-10-27, independent review follow-up)

- T1 (A1): Bind each observed checkout to exec_path `/usr/bin/<kind>`, argv[0]
  `<kind>` and the expected adapter; a Git exec with argv[0] `hg` must fail.
- T2 (A1): Block `clone(CLONE_UNTRACED)` and `clone3` for the target with a
  launcher-installed seccomp filter; the observer verifies the extra filter and
  the boundary controls must observe the block.
- T3 (A1): Track successful `chdir` per process with fork/clone inheritance;
  unknown cwd (fchdir, shared fs, symlink creation) fails closed. The checkout
  must run in `/work/case/<kind>source` after an observed fixture clone.
- T4 (A1): One strict trace grammar shared by observer and host; truncated argv,
  ellipsis, unknown line shapes and unfinished records are rejected. The host
  re-parses stored traces instead of trusting parsed calls.
- T5 (A1): Publish `target.pid` atomically and validate the published process.
- T6 (A2): Implement the pip-mercurial adapter with pinned pip 23.2.1 internals.
- T7 (A5): Extend the clean-install harness to runtime policy, real
  verification, DB promotion, listing and authenticated reuse.

## Plan deviation: pip repair form

The handoff described the fixed form as `-r=VALUE` (pip 23.3). Observed in the
sandbox image (Mercurial 7.0.1): `hg update --quiet -r=stable` exits 255 with
`parse error at 0: not a prefix: =`, while `--rev=stable` updates to `stable`
and `--rev=--config=...` is rejected as a revision. Paladin repairs to
`['--rev=' + rev]`. pip 23.3 is kept as an upstream-attached-revision control
that is expected to fail the ordinary-checkout check.

## Verified Facts

- In this repository, Docker 29.6.2 (linux, x86_64) runs the sandbox; the
  default container seccomp allows `clone(CLONE_UNTRACED|SIGCHLD)`, and a child
  created that way executed `/bin/true` without any execve line under
  `strace -f` (observed 2026-10-27 with image sha256:0109e899...).
- In this repository, existing `.paladin/cases.sqlite3` holds one legacy
  `mercurial-checkout-pinned-source-probe-v2` record; it stays retained and excluded.

## Review Decisions (2026-10-28, fresh-context code + security review)

Code review: 0 CRITICAL, 0 HIGH. Security review: 0 CRITICAL, 0 HIGH.

- fixed -> shared-fs cwd invalidation ignored trace position -> trace_grammar `shared` is index-keyed; test_shared_fs_or_fchdir_makes_exec_cwd_unknown (later thread keeps exec cwd)
- fixed -> new host error codes collapsed to case_operation_failed -> cli._case_error known set extended
- fixed -> host payload validation untested -> sandbox_runtime.validate_output + HostPayloadValidationTests (10 tampered fields)
- fixed -> case_probe.py shipped an unsandboxed host execution path -> removed from src (byte-identical copies remain in docs/evidence/cve-case-loop-final/)
- fixed -> stale docs (case-loop.md, README) -> rewritten for structural adapters, Docker observer, HMAC
- fixed -> container rm in finally could mask errors -> wrapped
- fixed -> host compared calls/exit but not alias flag -> validate_output compares calls, exit, path_alias_created
- fixed (revised) -> PID wait 60 s exceeded host 45 s -> host CASE_TIMEOUT_SECONDS 120; a 20 s PID wait caused target_not_started under Docker Desktop exec latency (eval run-20261028T015224Z, kept)
- fixed -> missing assertions / Git helper allowlist untested -> tests added (EPERM clone, exact helpers and near miss)
- fixed -> repair dispatch by AST class name vs rule id -> _repair_bytes(original, rule_id)
- fixed -> misleading pip comment -> corrected
- fixed -> (security M2) rename/link aliasing untraced -> rename, renameat, renameat2, link, linkat traced; non-tool aliasing sets path_alias_created and fails safe checks
- fixed -> (security L1) unpinned apt versions -> resolved versions recorded in hashed build log (git 1:2.47.3-0+deb13u1, mercurial 7.0.1-2, strace 6.13+ds-1); still not pinned
- deferred -> (security M1) in-process Mercurial Python hooks from a target-modified clone plus target-writable branch file can satisfy safe_* checks without a real checkout; risk argv checks are unaffected; the target controls its child environment so HGRCSKIPREPO-style mitigations do not hold -> documented limitation
- deferred -> (security L2) legitimate in-trace PID reuse fails closed -> availability only
- deferred -> (security L3) ReDoS not demonstrable; trace capped at 1 MB
- kept -> untraced-escape marker check retained as a commented sanity assertion

## Review Decisions (2026-10-29, M1 hardening, apt pinning, replay check)

- fixed -> (2026-10-28 security M1) target-writable branch file and in-process hg hooks could fake safe checks -> root replay of the observed argv in a clean root clone; host requires replayed_argv and replay_branch; verifier v5, observer v3; eval run-20261029T002031Z PASS
- fixed -> (2026-10-28 security L1) unpinned apt -> snapshot 20261027T000000Z + exact versions; sandbox-v6/build.log
- scoped -> (replay check MEDIUM) trace proves argv, not the target's own hg/git process behaviour under a target-controlled environment -> limitation stated in case-loop.md and final report; capturing envp of the decisive exec is a follow-up
- deferred -> (replay check LOW) set TMPDIR for root replay; https snapshot and hashed dpkg list; reap zombies or --init before replay; fixtures() with REPLAY_ENV; resize CASE_TIMEOUT_SECONDS for replay time -> next round, needs image rebuild and full re-evaluation
