"""Evaluate the bounded case loop on full public checkouts without file hints."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

from paladin.advisory import dispatch
from paladin.knowledge import _resource

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".validation-cache/blind-cve-eval"
EVIDENCE = ROOT / "docs/evidence/cve-case-loop-v2"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest(root):
    return {path.relative_to(root).as_posix(): sha(path) for path in sorted(root.rglob("*"))
            if path.is_file() and not any(part in {".git", "__pycache__", ".pytest_cache"}
                                         for part in path.relative_to(root).parts)}


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="ascii") as stream:
        json.dump(data, stream, indent=2, sort_keys=True, ensure_ascii=True)
        stream.write("\n")


def run_cli(label, action, project=None):
    command = [sys.executable, "-B", "-m", "paladin.cli", "cases", action,
               "--workspace", str(ROOT), "--json"]
    if project is not None:
        command += ["--project", str(project)]
    run = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=120, check=False)
    (EVIDENCE / (label + ".stdout.bin")).write_bytes(run.stdout)
    (EVIDENCE / (label + ".stderr.bin")).write_bytes(run.stderr)
    result = json.loads(run.stdout)
    save(EVIDENCE / (label + ".json"), {"command": command, "exit_code": run.returncode, "result": result})
    return result


def main():
    if EVIDENCE.exists():
        raise FileExistsError(EVIDENCE)
    sources = {name: CACHE / name for name in ("source", "fixed", "unrelated")}
    commits = {}
    for name, source in sources.items():
        run = subprocess.run(["git", "rev-parse", "HEAD"], cwd=source,
                             capture_output=True, check=True)
        commits[name] = run.stdout.decode("ascii").strip()
    frozen = {"kind": "root_only_candidate_scan_with_pinned_source_verification",
              "source_commits": commits, "source_manifests": {name: manifest(source) for name, source in sources.items()},
              "implementation": {path.name: sha(path) for path in (ROOT / "src/paladin").glob("*.py")},
              "script_sha256": sha(Path(__file__)),
              "limits": ["The positive external project is a Cookiecutter fork, not an independent implementation.",
                         "Static detection is broader than execution; only two pinned source identities are verified.",
                         "Candidate file locations are not supplied to the detector."]}
    save(EVIDENCE / "freeze.json", frozen)
    scans = {name: run_cli("scan-" + name, "scan", source) for name, source in sources.items()}
    if not scans["source"]["candidates"]:
        raise ValueError("positive_source_candidate_missing")
    auto = run_cli("auto-source", "auto", sources["source"])
    promoted = [item for item in auto["case_runs"] if item["status"] == "promoted"]
    if len(promoted) != 1:
        raise ValueError("positive_case_not_promoted")
    repeat = run_cli("auto-source-repeat", "auto", sources["source"])
    repeated = [item for item in repeat["case_runs"] if item["status"] == "promoted"]
    if len(repeated) != 1 or repeated[0]["case"]["case_id"] != promoted[0]["case"]["case_id"]:
        raise ValueError("promotion_not_idempotent")
    listed = run_cli("list-cases", "list")
    if promoted[0]["case"]["case_id"] not in {row["case_id"] for row in listed["cases"]}:
        raise ValueError("promoted_case_not_retrievable")
    repaired = CACHE / "repaired"
    shutil.copytree(sources["source"], repaired,
                    ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
    relative = promoted[0]["candidate"]["path"]
    shutil.copy2(promoted[0]["staged_source"], repaired / relative)
    args = {"pattern_id": "CVE-2022-24065",
            "pack_sha256": hashlib.sha256(_resource("prevention-pack.json")).hexdigest(),
            "guidance_sha256": hashlib.sha256(_resource("guidance-pack.json")).hexdigest()}
    guidance = dispatch(ROOT, "get_prevention_guidance", args)
    save(EVIDENCE / "guidance-reuse.json", guidance)
    if promoted[0]["case"]["case_id"] not in {row["case_id"] for row in guidance.get("verified_case_references", [])}:
        raise ValueError("promoted_case_not_reused")
    checks = {}
    python = ROOT / ".validation-cache/external-comparison/venv/Scripts/python.exe"
    probe = ROOT / "eval/external_mercurial_probe.py"
    for label, source in (("before", sources["source"]), ("after", repaired)):
        run = subprocess.run([str(python), "-B", str(probe), "--target", str(source)],
                             cwd=ROOT, capture_output=True, timeout=120, check=False)
        (EVIDENCE / ("hg-" + label + ".stdout.bin")).write_bytes(run.stdout)
        (EVIDENCE / ("hg-" + label + ".stderr.bin")).write_bytes(run.stderr)
        checks[label] = {"exit_code": run.returncode,
                         "result": json.loads(run.stdout) if run.returncode == 0 else None}
    save(EVIDENCE / "real-hg.json", {"probe_sha256": sha(probe), "checks": checks})
    unchanged = all(manifest(source) == frozen["source_manifests"][name] for name, source in sources.items())
    save(EVIDENCE / "result.json", {"status": "complete", "promoted_case": promoted[0]["case"],
                                    "source_candidate_count": len(scans["source"]["candidates"]),
                                    "fixed_candidate_count": len(scans["fixed"]["candidates"]),
                                    "unrelated_candidate_count": len(scans["unrelated"]["candidates"]),
                                    "source_unchanged": unchanged, "promotion_idempotent": True,
                                    "guidance_reused_case": True, "real_hg": checks})
    if not unchanged:
        raise ValueError("original_source_changed")
    print(json.dumps({"promoted": len(promoted), "source_candidates": len(scans["source"]["candidates"]),
                      "fixed_candidates": len(scans["fixed"]["candidates"]),
                      "unrelated_candidates": len(scans["unrelated"]["candidates"]),
                      "source_unchanged": unchanged, "idempotent": True,
                      "real_hg": {label: item["result"]["passed"] if item["result"] else None for label, item in checks.items()}}))


if __name__ == "__main__":
    main()
