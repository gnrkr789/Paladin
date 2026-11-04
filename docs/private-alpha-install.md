# Local private-alpha installation

The private alpha is `paladin==0.2.0a1`. Artifacts are local and unpublished.
Python 3.12 and uv are required for the reproducible validation harness.

Run from the checkout after the source and sandbox assets are stable:

```powershell
uv --cache-dir .cache/uv run --frozen --no-sync python scripts/build_private_alpha.py
```

The harness builds a versioned sdist and a wheel from that sdist in
`dist/private-alpha/`. It checks all Python modules and packaged resources
against the source bytes, including `resources/sandbox/*`.

Validation creates a fresh environment under the OS temporary directory at
`.validation-cache/private-alpha-install/venv`, outside the checkout. It removes
`PYTHONPATH`, `PYTHONHOME`, and `VIRTUAL_ENV`, installs dependencies from the frozen
uv export with hashes, then installs the wheel without an editable source link.
It checks dependency consistency, the installed CLI help, a deterministic
`cases scan` fixture, MCP protocol discovery, and installed module origins.
The discovery process uses isolated Python. No model is downloaded or executed.

Unless `--skip-runtime` is given, the harness then uses only the installed CLI
with a fresh workspace: `cases auto` must refuse with `runtime_not_configured`;
`cases runtime-build` builds the sandbox image from the installed assets; and
for Cookiecutter 2.1.0 and pip 23.2.1 (from `.validation-cache/`) it runs
`cases auto` (one promoted case each), `cases list` and a second `cases auto`
that must reuse the authenticated case. Project source trees are hashed before
and after. This needs a running Docker daemon.
The temporary environment is removed after verification.

Validation output is written locally (not tracked) to
`docs/evidence/private-alpha/package/`: command exit codes,
stdout and stderr logs, the frozen dependency requirements, source/resource
hashes, artifact hashes, module origins, scan results, and MCP tool discovery.
Only `report.json` with `status: PASS` confirms complete packaging validation.
To recheck existing artifacts without rebuilding:

```powershell
uv --cache-dir .cache/uv run --frozen --no-sync python scripts/build_private_alpha.py --skip-build
```

For a separate local environment, install the generated wheel:

```powershell
uv venv --python 3.12 .private-alpha-venv
uv pip install --python .private-alpha-venv/Scripts/python.exe --require-hashes -r docs/evidence/private-alpha/package/requirements.lock.txt
uv pip install --python .private-alpha-venv/Scripts/python.exe --no-deps dist/private-alpha/paladin-0.2.0a1-py3-none-any.whl
.private-alpha-venv/Scripts/paladin.exe --help
```

Before running `cases auto`, explicitly build and configure the sandbox image:

```powershell
.private-alpha-venv/Scripts/paladin.exe cases runtime-build --workspace C:/work/paladin-workspace --json
.private-alpha-venv/Scripts/paladin.exe cases scan --project C:/work/target-project --json
.private-alpha-venv/Scripts/paladin.exe cases auto --project C:/work/target-project --workspace C:/work/paladin-workspace --json
.private-alpha-venv/Scripts/paladin.exe cases list --workspace C:/work/paladin-workspace --json
```

The workspace directory must already exist. Runtime build needs a working Linux
Docker daemon and network access to obtain its pinned build dependencies. Target
execution uses the configured immutable image with networking disabled; no host
execution fallback exists. Configuration at `.paladin/runtime.json` binds the
image and observer identity to the current packaged runtime assets. Changed
assets require another explicit `cases runtime-build`. The two supported adapters
are Cookiecutter CVE-2022-24065 and pip Mercurial CVE-2023-5752. `cases list`
includes both by default; `--cve` selects one supported CVE.

Installation and discovery evidence do not establish sandbox runtime behavior,
vulnerability prevention, blocking, or general security readiness. Runtime
verification requires the separate private-alpha case evidence.
