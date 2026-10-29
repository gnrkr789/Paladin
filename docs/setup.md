# M1 local Milvus setup and diagnostics

Validated environment: Windows PowerShell, Python 3.12.10, Docker Desktop Linux engine. The package requires Python 3.11+. Product documentation, messages and supported text inputs are English only.

## Install

```powershell
uv --cache-dir .cache/uv sync --locked
.\.venv\Scripts\paladin.exe setup --json
.\.venv\Scripts\paladin.exe doctor --json
```

Setup downloads pinned images if necessary, starts a workspace-specific Compose project and initializes three synthetic diagnostic samples. It preserves unrelated projects and reports port conflicts instead of resolving them automatically. `setup --no-start --json` only writes configuration and returns `configured`; it does not claim DB readiness. Pass the same `--workspace` when running from another directory.

Versions: Milvus 2.6.25, PyMilvus 2.6.17, etcd v3.5.25, MinIO RELEASE.2024-12-18T13-15-44Z. Python dependencies are pinned in uv.lock. Image tags are fixed; Compose does not enforce digest pins. Original Compose and observed digests are in [M1 evidence](evidence/m1/).

## State and repeated runs

Workspace `.paladin/` holds config.toml, packaged compose.yaml, manifest.json, metadata.sqlite3 and persistent data/etcd, data/minio, data/milvus bind mounts. Model artifacts and the semantic manifest are added by M2. This directory is excluded from version control.

The canonical Compose file is `src/paladin/resources/compose.yaml`, also included in wheels. Setup preserves existing configuration and identity, upserts diagnostic samples by stable IDs and rejects incompatible schemas without deletion. Modified Compose is preserved and reported as a conflict. Arbitrary ports, remote endpoints, diagnostic models and manual Compose edits are unsupported. State paths must resolve inside the workspace, including symlinks and nested mounts.

## Read-only doctor

Doctor never starts services, creates collections or reseeds data. It checks configuration, JSON/SQLite identity, server version, schema, diagnostic encoder identity, three exact sample records and top-1 retrieval for each sample. `doctor --semantic` additionally checks the M2 model and semantic index.

| Status | Exit | Meaning |
|---|---:|---|
| configured | 0 | Setup files only |
| ready | 0 | Operational diagnostic checks pass |
| degraded | 1 | A connected component fails a compatibility/data check |
| unavailable | 1 | Configuration/metadata or DB access fails |
| error | 1 | Setup conflict, startup or initialization failure |

M1 uses `diagnostic-token-hash-v1`, 64D, `m1-diagnostic-v1`: a local normalized token hash for synthetic samples. It is not semantic CVE retrieval. Every result has `security_ready=false`.

## Stop and resume

```powershell
$paladinProject = (Get-Content .paladin/manifest.json -Raw | ConvertFrom-Json).compose_project
docker compose --project-name $paladinProject --file .paladin/compose.yaml stop
docker compose --project-name $paladinProject --file .paladin/compose.yaml up -d --wait
.\.venv\Scripts\paladin.exe doctor --semantic --json
```

Run doctor before setup/reindex to verify persisted data. Container health may become ready before collection queries; a transient failure is reported honestly. No deletion, volume reset, backup or upgrade command is implemented.

Only 127.0.0.1:19530 and 127.0.0.1:9091 are published; etcd and MinIO have no host ports. This is a single-user local deployment; agent read-only authorization is future MCP work.

[Actual Docker persistence/failure evidence](evidence/m1-report.md) is separate from unit tests, which use service doubles. Host reboot, whole-stack loss and backup restore are not validated.
