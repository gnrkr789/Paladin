# Handoff: private alpha, verifier v4 (2026-10-27)

Plan: `docs/plans/paladin-private-alpha.plan.md` (Status: building, T1-T7,
plan deviation and Verified Facts recorded there). Nothing committed; no
publication. Preserve all earlier evidence directories (`sandbox/`, partial
`sandbox/cookiecutter-after/{0,1}`) as historical records.

## Done in this session (code)

- `resources/sandbox/trace_grammar.py` (new, copied into the image and loaded by
  the host via `sandbox_runtime.trace_grammar()`): strict strace grammar; joins
  unfinished/resumed records; rejects ellipsis/truncated/unknown lines,
  interrupted records, execveat, successful clone3 and successful
  CLONE_UNTRACED clones. Derives per-exec cwd from chdir + fork/clone
  inheritance; CLONE_FS/CLONE_THREAD or fchdir gives cwd None. Symlinks are
  flagged only when created by a non-hg/git process image (hg lock files are
  symlinks).
- `target.py`: installs a seccomp filter before publishing its PID
  (clone with CLONE_UNTRACED -> EPERM, clone3 -> ENOSYS, foreign arch/x32 ->
  kill); atomic `target.pid` publish; `pip-mercurial` adapter loading the
  supplied file as `pip._internal.vcs.mercurial` on pinned pip 23.2.1
  (`/opt/pip-runtime`), calling `fetch_new(..., verbosity=0)`.
- `observer.py` (OBSERVER_ID `docker-strace-execve-v2`): waits for a valid PID
  whose cmdline is the launcher; checks uid/CapEff/NoNewPrivs and
  `Seccomp_filters == observer + 1`; records target_pid, target_cwd,
  symlink_created, checkout_directory_real.
- `Dockerfile`: base pinned by digest; pip 23.2.1 wheel installed with hash;
  read-only `/opt/paladin/gitconfig` safe.directory (GIT_CONFIG_COUNT is dropped
  by Git local transport, which made every Git clone exit 128 before).
- `sandbox_runtime.py`: `ASSET_NAMES` (4 files), host re-parses each trace and
  compares to observer calls, extra credential checks, create timeout 120 s,
  target wait 30 s, boundary controls `untraced-clone-blocked`,
  `clone3-unavailable`, and no `untraced-escape` marker.
- `case_verification.py` (VERIFIER_ID `mercurial-isolated-observer-v4`):
  `derive_checks` re-parses traces; every exec must be `/usr/bin/<kind>` with
  argv[0] `<kind>` (only exact Git upload-pack helpers allowed); requires the
  exact fixture clone, checkout cwd `/work/case/<kind>source`, no target
  symlink, real checkout dir. pip probe cases are separate (no `-rdefault`).
- `pip_case_adapter.py`: repair is `['--rev=' + rev]` (see plan deviation:
  `-r=stable` fails in Mercurial 7.0.1; pip 23.3 is now a broken-fix control).
- Tests: new `tests/observer_fixtures.py`; rewritten
  `test_isolated_verification.py`, `test_sandbox_runtime.py`; updated
  `test_case_verification.py`, `test_case_runtime.py`, `test_pip_candidate.py`.

## Real evidence produced

- Old image, pre-fix: CLONE_UNTRACED child exec was invisible to `strace -f`
  (recorded in plan Verified Facts; command output not saved to a file).
- `docs/evidence/private-alpha/sandbox-v2/boundary.json`: PASS on image
  sha256:cb3f9ba6... (an intermediate build). The image was rebuilt twice
  afterwards; boundary checks must be re-run on the current image.
- Current runtime `.paladin/runtime.json` and `sandbox-v2/runtime.json`:
  image sha256:609a38562aec41e77c23eea81916358272c11e13e0cb38a8d3ea700c0e2c4e5b
  (built before the last two host-only edits; Dockerfile/observer/target/grammar
  unchanged since then, so it should still match - verify with load_runtime).
- Ad hoc per-case runs on that image (stdout only, not saved): Cookiecutter
  2.1.0 all 6 cases observed with expected argv/cwd (git now clones and checks
  out `stable`); pip 23.2.1 stable/--debugger/--literal-branch observed with
  expected argv/cwd; one pip case hit the old 5 s target-wait timeout (since
  raised to 30 s).
- `docs/evidence/private-alpha/eval-v4/cookiecutter-2.1.0.auto.json`: FAILED
  run (`sandbox_execution_failed`) from before the git/symlink fixes. Keep it.
- `eval-v4/*.before.sha256`: source hash snapshots of the four external roots.
- Eval workspace: `.validation-cache/private-alpha-eval/ws` (runtime.json is an
  old copy; re-copy from `.paladin/runtime.json`).

## Tests

`python -m unittest tests.test_isolated_verification tests.test_case_verification
tests.test_case_pipeline tests.test_case_runtime tests.test_pip_candidate
tests.test_candidate_scan tests.test_sandbox_runtime tests.test_case_auth`
-> 51 tests OK (mocked observations; not Docker evidence). Full suite not run
after these changes; the 4 earlier failures/errors (actionable_guidance,
patch_context, two m3_mcp) are still unresolved.

## Next steps

1. Rebuild/confirm runtime; rerun `run_boundary_checks` into a new evidence dir.
2. `cases auto` on cookiecutter-2.1.0 (expect promote), cookiecutter-2.1.1
   (expect 0 candidates), pip-23.2.1 (expect promote with `--rev=`), pip-23.3
   (0 candidates); then `cases list` and a reuse run; then compare source hashes
   with `eval-v4/*.before.sha256`.
3. Real adversarial controls through `run_observed` + `derive_checks`: Git exec
   with argv[0] `hg`, checkout in another cwd, pip 23.3 `-r=` bytes as "after".
4. Full unit suite; investigate the 4 pre-existing failures.
5. Fresh-context security review (code-reviewer + security-reviewer) of the diff.
6. T7: extend `scripts/build_private_alpha.py` (runtime-build, real auto,
   list, reuse in the clean install), then build wheel/sdist and run it; update
   `docs/private-alpha-install.md` (it still says `-r=`-agnostic text; check).
7. Final report with artifact/source/image hashes, failures and limits.

## Known limitations to report

- Path aliasing by target `rename` during execution is not traced; only
  symlink creation and the final lstat are checked.
- hg python hooks from a target-modified clone could act inside a trusted
  hg image (no exec). Branch file is still target-writable; it is one input,
  not the sole success criterion.
- apt packages in the image are not version-pinned; image ID is the identity.
