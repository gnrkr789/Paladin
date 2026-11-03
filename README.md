<p align="center">
  <img src="docs/assets/paladin-hero.svg" alt="Paladin: CVE-grounded prevention and proof for AI coding agents" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.2.0a1-3451d1" alt="version 0.2.0a1">
  <img src="https://img.shields.io/badge/python-3.11%2B-3776ab" alt="python 3.11+">
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Apache-2.0">
  <img src="https://img.shields.io/badge/tests-344%20passing-2fbf71" alt="344 unit tests passing">
</p>

Paladin stops AI coding agents from reintroducing known CVE patterns. It tells
the agent what the problem is and how to avoid it; the agent writes its own fix.

- **Prevention cards** for 524 Python web CVEs, searchable by the agent over MCP
  (e5 + BM25 hybrid). 30 were checked against the patch by an agent (Codex);
  471 were drafted from advisory text and then checked against the fix diff by
  a model (`patch_checked`); 23 remain `candidate`.
- **Edit-time hook** for Claude Code and Codex, with no model or network call:
  an exact CVE match blocks the turn with the CVE, line, cause and fix
  direction; 125 rules drafted from the cards add non-blocking review notes.
- **Dependency check** (`paladin deps check`, MCP `check_dependencies`, and the hook
  when an agent edits a dependency file): pinned versions against the PyPI affected
  ranges of 520 collected CVEs, most of which are library-internal and have no code rule.
- **Proof loop**: reproduces a CVE and verifies a repair inside an isolated
  Docker observer before a case is recorded.

## Tested

<p align="center">
  <img src="docs/assets/evaluation.svg" alt="Measured results" width="100%">
</p>

| Test | Result |
|---|---|
| Cookiecutter 2.1.0, CVE-2022-24065 (detect, reproduce, repair, verify) | pass |
| pip 23.2.1, CVE-2023-5752 (same) | pass |
| Upstream-fixed versions (Cookiecutter 2.1.1, pip 23.3) | 0 false alarms |
| Attacks on the verifier: disguised binary, injected env, wrong checkout dir, fake output | all rejected |
| Sandbox boundary controls | 7/7 |
| Unseen projects, first scan of 3 sets | 2/6, 8/10 (1 FP), 2/5 |
| Same 3 sets after fixes | 21/21, 0 FP |
| Claude Code session, ported vulnerable code | blocked, agent fixed it |
| Clean install from wheel | pass |
| Search, fresh held-out questions (hit@5 / MRR) | 0.831 / 0.697 and 0.873 / 0.736 |
| Review rules, first scan of 4,055 site-packages files | 112 of 125 rules silent; pickle.load 37 files; 1 rule over 50 files not shipped |
| Rewritten cards audited by a second model (Codex), sample of 30 | 30 better than the draft; 10 exact, 20 with a side claim to fix |
| Same 207 cards after correction, Fable audit of a new sample of 30 | 29 exact, 1 with a minor omission |
| Unit tests | 344 pass |

Evidence: [docs/evidence/private-alpha/final-report.md](docs/evidence/private-alpha/final-report.md).

## How it works

<p align="center">
  <img src="docs/assets/case-loop.svg" alt="Scan, reproduce, repair, verify, promote" width="100%">
</p>

## Quick start

Windows only for now (Linux and macOS are untested). Python 3.12 recommended (on 3.11 the
first `patterns index` re-embeds the cards, about 90 s), [uv](https://docs.astral.sh/uv/), Docker Desktop.

Once per user (search state goes to the Paladin home: `PALADIN_HOME`, or
`%USERPROFILE%\.paladin` on Windows, `~/.local/share/paladin` elsewhere):

```powershell
uv --cache-dir .cache/uv sync --locked
.\.venv\Scripts\paladin.exe setup --json
.\.venv\Scripts\paladin.exe model prepare --json      # 487 MB, embeds search queries
.\.venv\Scripts\paladin.exe patterns index --json     # uses packaged vectors
```

Per project (hook, dependency check and MCP checks read the project; MCP search
reads the home):

```powershell
.\.venv\Scripts\paladin.exe hook install --workspace C:/projects/example
.\.venv\Scripts\paladin.exe hook install --host codex --workspace C:/projects/example
.\.venv\Scripts\paladin.exe deps check --workspace C:/projects/example
.\.venv\Scripts\paladin.exe mcp install --workspace C:/projects/example
.\.venv\Scripts\paladin.exe mcp install --host codex --workspace C:/projects/example
```

`mcp install` writes the project's `.mcp.json` (Claude Code asks once to approve it) or a
managed block in `.codex/config.toml`. Codex runs a project's hook and reads its config
only after you trust the project (`/hooks` for the hook).

Packaged vectors match the locked onnxruntime, tokenizers and numpy versions; a
plain `pip install` of the wheel gets newer ones, and `patterns index` then
embeds the cards locally (about 90 s). The hook needs no model, index or Docker.

Proof loop: `cases runtime-build`, then `cases auto --project <dir> --workspace <dir>`.

## Limits

Two exact CVE rules block; the other rules only advise. Single-file static
checks. Patch checks are model reviews, not human review. A clean result is
not a security verdict. Project text is English ASCII.

## Docs

[Hook](docs/hook.md) | [Case loop](docs/case-loop.md) | [MCP](docs/mcp.md) |
[Setup](docs/setup.md) | [Plans](docs/plans/)

## License

Apache-2.0. Bundled CVE records, patches and advisory data keep their own
licenses: [data/THIRD_PARTY.md](data/THIRD_PARTY.md), [NOTICE](NOTICE).
