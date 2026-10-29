"""Confirm final case policy, controls and reuse without candidate file hints."""
import asyncio
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

from paladin.case_pipeline import verified_case_references
from paladin.mcp_server import WorkerRunner

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".validation-cache/blind-cve-eval"
EVIDENCE = ROOT / "docs/evidence/cve-case-loop-final"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(name, value):
    with (EVIDENCE / name).open("x", encoding="ascii") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=True, sort_keys=True)
        stream.write("\n")


def command(label, action, source, workspace=ROOT):
    args = [sys.executable, "-B", "-m", "paladin.cli", "cases", action, "--project", str(source),
            "--workspace", str(workspace), "--json"]
    run = subprocess.run(args, cwd=ROOT, capture_output=True, timeout=120, check=False)
    (EVIDENCE / (label + ".stdout.bin")).write_bytes(run.stdout)
    (EVIDENCE / (label + ".stderr.bin")).write_bytes(run.stderr)
    value = json.loads(run.stdout)
    save(label + ".json", {"command": args, "exit_code": run.returncode, "result": value})
    return value


def main():
    if EVIDENCE.exists():
        raise FileExistsError(EVIDENCE)
    (EVIDENCE / "implementation").mkdir(parents=True)
    hashes = {}
    for source in (ROOT / "src/paladin").glob("*.py"):
        shutil.copy2(source, EVIDENCE / "implementation" / source.name)
        hashes[source.name] = digest(source)
    save("implementation.json", {"files": hashes, "runner_sha256": digest(Path(__file__))})
    before = verified_case_references(ROOT, "CVE-2022-24065")
    positive = command("positive-auto", "auto", CACHE / "source")
    promoted = [row for row in positive["case_runs"] if row["status"] == "promoted"]
    if len(promoted) != 1:
        raise ValueError("positive_not_promoted")
    fixed = command("fixed-auto", "auto", CACHE / "fixed")
    unrelated = command("unrelated-auto", "auto", CACHE / "unrelated")
    if fixed["candidates"] or unrelated["candidates"]:
        raise ValueError("unexpected_control_candidate")
    forged = CACHE / "forged-source"
    (forged / "cookiecutter").mkdir(parents=True)
    original = (CACHE / "source/cookiecutter/vcs.py").read_bytes()
    (forged / "cookiecutter/vcs.py").write_bytes(original + b"\nprint('{\"outcomes\": []}')\nraise SystemExit(0)\n")
    forged_result = command("forged-auto", "auto", forged)
    if not forged_result["candidates"] or any(row["status"] == "promoted" for row in forged_result["case_runs"]):
        raise ValueError("forged_target_not_blocked")
    control_workspace = CACHE / "control-workspace"
    control_workspace.mkdir()
    control = command("upstream-auto", "auto", ROOT / ".validation-cache/external-comparison/upstream/cookiecutter", control_workspace)
    if len([row for row in control["case_runs"] if row["status"] == "promoted"]) != 1:
        raise ValueError("second_pinned_variant_failed")
    after = verified_case_references(ROOT, "CVE-2022-24065")
    if after != before:
        raise ValueError("control_or_forgery_changed_case_store")
    mcp = asyncio.run(WorkerRunner(CACHE / "source", timeout=90).call("scan_cve_candidates", {}))
    save("mcp-scan.json", mcp)
    if not mcp.get("inspection_performed") or len(mcp.get("candidates", [])) != 1:
        raise ValueError("mcp_scan_failed")
    tests = [sys.executable, "-B", "-m", "unittest", "-q",
             "tests.test_case_pipeline.CasePipelineTests.test_legacy_verified_record_is_not_exposed",
             "tests.test_case_verification.CaseVerificationTests.test_unpinned_target_cannot_execute_or_promote",
             "tests.test_case_verification.CaseVerificationTests.test_claimed_flags_cannot_override_captured_calls"]
    run = subprocess.run(tests, cwd=ROOT, capture_output=True, timeout=120, check=False)
    (EVIDENCE / "security-regressions.stdout.bin").write_bytes(run.stdout)
    (EVIDENCE / "security-regressions.stderr.bin").write_bytes(run.stderr)
    if run.returncode:
        raise ValueError("security_regression_failed")
    save("result.json", {"status": "complete", "positive_promoted": 1,
                         "active_case_count": len(after["cases"]), "fixed_candidates": 0,
                         "unrelated_candidates": 0, "forged_candidate_promoted": False,
                         "second_pinned_variant_promoted": True, "mcp_candidates": 1,
                         "security_regressions_exit_code": run.returncode,
                         "case_id": promoted[0]["case"]["case_id"]})
    print("FINAL_CASE_LOOP_CONFIRMED")


if __name__ == "__main__":
    main()
