# M2 advisory knowledge and local semantic retrieval

The supported interface and all authored knowledge are English only. Use English technical text with printable ASCII, tabs and line breaks. Korean, mixed-script queries, non-ASCII characters and other control characters return `invalid_request` before model or database access. No language detection, translation or multilingual fallback is provided. ASCII alone cannot prove a sentence is English.

## Prepare and use

Run from the repository root after Docker Desktop is available:

```powershell
uv --cache-dir .cache/uv sync --locked
.\.venv\Scripts\paladin.exe setup --json
.\.venv\Scripts\paladin.exe patterns validate --json
.\.venv\Scripts\paladin.exe model prepare --json
.\.venv\Scripts\paladin.exe patterns index --json
.\.venv\Scripts\paladin.exe search 'Windows UNC paths in safe_join' --limit 3 --family path_traversal --json
.\.venv\Scripts\paladin.exe patterns status --json
.\.venv\Scripts\paladin.exe doctor --semantic --json
```

Use the same `--workspace` for setup, indexing and search. Limits are 1..20. Families: `path_traversal`, `sql_injection`, `ssrf`, `command_injection`, `unsafe_deserialization`.

Only explicit `model prepare` downloads from the pinned Hugging Face revision. Artifacts total 487,351,240 bytes and live in `.paladin/models/<revision>/`. Every artifact is hash checked; a mismatched existing file is preserved and reported as an error. Search and indexing never download missing files.

## Results and boundaries

Each match returns the full CVE advisory card, cause, prerequisites, observed patch, prevention direction, limitations, evidence URLs/paths/hashes, fixture specifications and source-claimed affected versions. Every card is `source_observed` (`agent_source_comparison`), not human approved. Its two fixtures are `specification_only`; affected versions are `source_claims_not_normalized`. Version applicability is not computed for installed dependencies.

Cosine similarity ranks reference candidates. It is not vulnerability probability or a blocking verdict. Safe code may retrieve the same relevant references. Callers must verify platform, version, trust boundaries and protective conditions. All responses retain `security_ready=false`; enforcement and sharing remain disabled.

Empty/oversized queries, unsupported characters or invalid limits return `invalid_request`; unknown families return `unsupported`. Missing/stale index, model or DB returns `unavailable`, never a safety claim or `no_known_match`. CLI failures exit 1.

## Model and index identity

The pinned encoder remains `intfloat/multilingual-e5-small`, revision `614241f622f53c4eeff9890bdc4f31cfecc418b3`, MIT according to its model card. Its architecture supports more languages, but Paladin's supported product interface is English only. Keeping the validated artifact avoids an unrelated model migration; it does not enable Korean input.

Inference uses ONNX CPUExecutionProvider, 384 dimensions, query/passage prefixes, attention-mask mean pooling and L2 normalization. Intra-op threads: 4; inter-op: 1. No remote repository Python executes, and ONNX telemetry is disabled. Inputs longer than 512 tokens fail rather than being silently truncated.

The separate M1 64D diagnostic collection remains intact. M2 collection identity includes workspace, pack hash, model files/revision, preprocessing, runtime versions and `english-ascii-v1` text policy. Policy changes invalidate previous manifests. Run `patterns index` to rebuild; prior collections are not automatically deleted.

Index creation embeds all cards, writes and verifies rows, then records the active JSON/SQLite manifest. `doctor --semantic` checks model hashes, schema, card IDs and row pack/model metadata. It is a readiness check, not a retrieval-quality evaluation.

## Evidence and evaluation

- [30-CVE catalog](data/m2-catalog.md)
- [Bundled pack](../src/paladin/resources/prevention-pack.json)
- [Model file lock](../src/paladin/resources/embedding-model.json)
- [Results and limitations](evidence/m2-report.md)

The wheel includes code, Compose, pack, schema and model specification; it excludes raw source snapshots and model weights. Original third-party snapshots and raw `source_affected` fields are retained verbatim for provenance, outside the authored-text language contract.

`eval/m2-queries.json` now contains 20 English development queries. Ten paraphrase earlier unsupported-language intents; results are a new protocol, not directly comparable to the historical mixed-language evaluation. The exact prior fixture and results are retained in `docs/evidence/history/m2-before-english-only.zip`. Current evaluation never imports that archive. Django accounts for 24/30 cards; generalization and vulnerability-prevention effectiveness remain untested.
