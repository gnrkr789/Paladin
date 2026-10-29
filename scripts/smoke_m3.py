"""Bounded M3 protocol/package/deadline evidence; never configures a host."""
import argparse
import asyncio
import hashlib
from importlib import metadata
import json
from pathlib import Path
import sys
import tempfile
import time

from mcp import Client, StdioServerParameters

from paladin.advisory import INPUT_SCHEMAS, MAX_RESULT_BYTES


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def state_snapshot(root):
    from paladin.embedding import model_lock, model_directory
    from paladin.knowledge import load_pack
    paths = [root / ".paladin" / name for name in
             ["config.toml", "manifest.json", "metadata.sqlite3", "semantic-index.json", "compose.yaml"]]
    paths += [root / e["snapshot_path"] for p in load_pack()["patterns"] for e in p["evidence"]]
    paths += [model_directory(root) / e["name"] for e in model_lock()["files"]]
    return {str(path.relative_to(root)): digest(path) for path in set(paths) if path.is_file()}


async def protocol_smoke(root, installed=False):
    from paladin.knowledge import _resource, load_pack
    import paladin
    report = {"mode": "installed" if installed else "live", "sdk_version": metadata.version("mcp"),
              "paladin_module": str(Path(paladin.__file__).resolve()), "calls": []}
    pack_sha = hashlib.sha256(_resource("prevention-pack.json")).hexdigest()
    before = state_snapshot(root) if not installed else {}
    started = time.monotonic()
    async with Client(StdioServerParameters(command=sys.executable,
                      args=["-B", "-m", "paladin.cli", "mcp", "--workspace", str(root)]),
                      read_timeout_seconds=35) as client:
        report["protocol_version"] = client.protocol_version
        tools = (await client.list_tools()).tools
        assert {t.name for t in tools} == set(INPUT_SCHEMAS)
        report["tools"] = [t.model_dump(mode="json", by_alias=True, exclude_none=True) for t in tools]

        async def call(name, args):
            now = time.monotonic()
            response = await client.call_tool(name, args)
            result = response.structured_content
            assert result is not None
            assert json.loads(response.content[0].text) == result
            size = len(json.dumps(response.model_dump(mode="json", by_alias=True, exclude_none=True),
                                  ensure_ascii=True).encode())
            assert size <= MAX_RESULT_BYTES
            assert not any(result[k] for k in ["security_ready", "enforcement_enabled", "sharing_enabled"])
            report["calls"].append({"tool": name, "seconds": time.monotonic() - now,
                                    "serialized_result_bytes": size, "is_error": response.is_error,
                                    "result": result})
            return result

        status = await call("get_knowledge_status", {})
        assert status["status"] == ("unavailable" if installed else "ready"), status
        search = await call("search_prevention_patterns", {"intent": "Windows UNC paths in safe_join", "limit": 1})
        if installed:
            assert search["status"] == "unavailable"
            pattern = load_pack()["patterns"][0]
        else:
            assert search["status"] == "complete", search
            pattern = search["matches"][0]["pattern"]
            assert pattern["pattern_id"] == "CVE-2024-49766", pattern
            assert search["manifest"]["pack_sha256"] == pack_sha
            report["ranking_check"] = "Expected M2 UNC reference retained at rank 1."
        args = {"pattern_id": pattern["pattern_id"], "pack_sha256": pack_sha}
        evidence = await call("get_pattern_evidence", args)
        assert evidence["status"] == "complete"
        args.update(include_excerpt=True, evidence_ids=[evidence["evidence"][0]["evidence_id"]])
        evidence = await call("get_pattern_evidence", args)
        if installed:
            assert evidence["status"] == "partial"
            assert evidence["omissions"][0]["reason"] == "content_unavailable"
        else:
            assert evidence["evidence"][0]["hash_verified"]
            assert evidence["evidence"][0]["excerpt"]
        check = await call("check_changes", {})
        assert check["status"] == "unsupported" and not check["inspection_performed"]
        assert "receipt" not in check
        invalid = await call("search_prevention_patterns", {"intent": "\ud55c"})
        assert invalid["status"] == "invalid_request"
    report["seconds_with_shutdown"] = time.monotonic() - started
    if not installed:
        after = state_snapshot(root)
        assert before == after, "Authoritative files changed during read-only MCP calls"
        report["state_hashes"] = before
        report["authoritative_files_unchanged"] = True
    else:
        assert not any(root.iterdir()), "Installed smoke wrote workspace files"
        report["empty_workspace_preserved"] = True
    report["status"] = "PASS"
    return report


async def timeout_smoke(root):
    from paladin.mcp_server import WorkerRunner
    runner = WorkerRunner(root)
    started = time.monotonic()
    result = await runner.call("get_knowledge_status", {},
                               command=[sys.executable, "-c", "import time; time.sleep(60)"])
    elapsed = time.monotonic() - started
    assert result["reason"] == "deadline_exceeded", result
    assert 30 <= elapsed <= 32.5, elapsed
    assert not runner.active_pids
    recovery = await runner.call("check_changes", {})
    assert recovery["status"] == "unsupported"
    return {"status": "PASS", "deadline_seconds": 30, "elapsed_seconds": elapsed,
            "cleanup_tolerance_seconds": 2.5, "active_pids_after": sorted(runner.active_pids),
            "timeout_result": result, "next_call": recovery}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["live", "installed", "timeout"], required=True)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.mode == "installed":
            with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
                report = asyncio.run(protocol_smoke(Path(temp), installed=True))
        elif args.mode == "timeout":
            report = asyncio.run(timeout_smoke(args.workspace.resolve()))
        else:
            report = asyncio.run(protocol_smoke(args.workspace.resolve()))
        code = 0
    except Exception as exc:
        report = {"status": "FAIL", "mode": args.mode, "error": f"{type(exc).__name__}: {str(exc)[:1000]}"}
        code = 1
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k not in {"calls", "tools", "state_hashes"}}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
