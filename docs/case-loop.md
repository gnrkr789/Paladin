# Local CVE case loop

Two rules are supported: Cookiecutter-shaped checkout calls for CVE-2022-24065
and pip `Mercurial.get_base_rev_args` returning `["-r", rev]` for CVE-2023-5752.
The scanner receives a project root, not a vulnerable file location. It reports
candidates and unsupported observations; no candidate is a security verdict.
Unresolved dynamic argv and source parsing limits make coverage partial. Git
metadata, Paladin state and Python caches are skipped.

```powershell
.venv/Scripts/python.exe -B -m paladin.cli cases runtime-build --workspace C:/Paladin --json
.venv/Scripts/python.exe -B -m paladin.cli cases scan --project C:/projects/example --json
.venv/Scripts/python.exe -B -m paladin.cli cases auto --project C:/projects/example --workspace C:/Paladin --json
.venv/Scripts/python.exe -B -m paladin.cli cases list --workspace C:/Paladin --json
```

`auto` stages one source snapshot, applies the deterministic repair for the
matched source structure (`--` before the Mercurial checkout target; or
`["--rev=" + rev]` for pip) and verifies before/after copies. Exact source
fingerprints are not required. Unsupported structures fail closed.

Target source executes only inside the explicitly built Docker runtime
(`mercurial-isolated-observer-v5`, observer `docker-strace-execve-v3`): no
network, read-only root filesystem, no host mounts, all capabilities dropped
except the observer's ptrace, uid 65534 with no-new-privileges, resource and
time limits. The launcher adds a seccomp filter that denies untraceable process
creation (`clone` with `CLONE_UNTRACED`, and `clone3`). A separate root strace
observer records execs, working directories and exits; target stdout is never
evidence. The host re-parses every stored trace with the same strict grammar.
A check passes only for an exec of `/usr/bin/hg` or `/usr/bin/git` whose argv[0]
matches, after the observed fixture clone, in the cloned checkout directory.
There is no host execution fallback.

The original project is preserved. The staged source is a proposed file change,
not a complete project integration test. Risk inputs, ordinary checkouts and
literal leading-hyphen Hg revisions are checked against real local Mercurial/Git
fixtures. No dangerous exploit is executed.

Cases are stored in `.paladin/cases.sqlite3`, with immutable content IDs and
source/evidence snapshots in `.paladin/case-evidence/`. Evidence is signed with a
host HMAC key (`.paladin/case-auth.key`) that never enters the container.
Promotion requires risk observed before, risk blocked after, compatible behavior
and exact identities. Human review remains false.

Before reuse, references are checked against the authenticated evidence, the
current verifier and runtime identity, candidate identity, source snapshots and
rederived outcomes. Legacy or damaged records are retained but excluded; their
presence yields partial status. Authentication does not defend against a local
principal who can read or rewrite the host key.
New verifier revisions can be appended for the same project/candidate while
preserving legacy records. Contradictory evidence for the same verifier remains
an error; adding a new revision does not make a legacy record reusable.

The functional outcome of ordinary and literal checkouts is not read from the
target's clone. After all target processes exit, the root observer replays the
exact observed checkout argv (only fixed ordinary or repaired shapes) in a fresh
root-owned clone of the fixture with a clean environment and repository config
ignored, and reports that branch. Target-written files, repository hooks and
environment injection into the target's own hg/git processes therefore cannot
produce a passing check. Symlink, rename and hard-link creation by target code is
traced and fails the safe checks.

Known limits: the verdict covers the recorded argument-injection cases and the
checkout outcome of the observed argv under clean hg/git, not what the target's
own hg/git process did with a target-controlled environment, and not
whole-project security. Observer-side
failures are reported by the CLI as `sandbox_observation_failed`. Docker CLI
timeouts are retried up to three times in fresh containers and counted as
`infrastructure_retries`.

`get_prevention_guidance` includes valid local case references and a separate
reference revision when the workspace has a case database. The base pack and
semantic index are not rewritten. `scan_cve_candidates` is a read-only MCP tool
that scans the configured workspace with no file-location argument. Automatic
verification and DB writes use the explicit CLI `cases auto` operation.

See [external evaluation](evidence/cve-case-loop-final/report.md) for source
commits, the public fork limitation and actual promotion results.
