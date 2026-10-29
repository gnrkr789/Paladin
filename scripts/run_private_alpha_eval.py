"""Run the private-alpha external evaluation against the configured Docker runtime.

Every result, including failures, is written to a new timestamped evidence
directory. Project source trees are hashed before and after to show they stay
unchanged. Nothing here executes project code outside the sandbox runtime.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / ".validation-cache" / "upstream"
PROJECTS = ROOT / ".validation-cache" / "private-alpha-projects"
SUBJECTS = [
    ("cookiecutter-2.1.0", UPSTREAM / "cookiecutter-2.1.0", "affected", 1),
    ("cookiecutter-2.1.1", UPSTREAM / "cookiecutter-2.1.1", "upstream-fixed", 0),
    ("pip-23.2.1", PROJECTS / "pip-23.2.1", "affected", 1),
    ("pip-23.3", PROJECTS / "pip-23.3", "upstream-attached-revision", 0),
]
COOKIECUTTER_VCS = UPSTREAM / "cookiecutter-2.1.0" / "cookiecutter" / "vcs.py"
PIP_AFFECTED = PROJECTS / "pip-23.2.1" / "src" / "pip" / "_internal" / "vcs" / "mercurial.py"
PIP_UPSTREAM_FIX = PROJECTS / "pip-23.3" / "src" / "pip" / "_internal" / "vcs" / "mercurial.py"

# Adversarial "before" sources. Each clones the real fixture, then forges one property.
MASQUERADE = b'''import os, subprocess
def clone(repo_url, checkout=None, clone_to_dir=".", no_input=False):
    os.makedirs(clone_to_dir, exist_ok=True)
    subprocess.check_output(["hg", "clone", "/fixtures/hgsource"], cwd=clone_to_dir)
    subprocess.run(["hg", "checkout", checkout], executable="/usr/bin/git",
                   cwd=clone_to_dir + "/hgsource")
'''
# Correct-looking argv, but the child hg gets an injected PYTHONPATH, so its
# behaviour is target-controlled; the decisive exec must not count.
ENV_INJECTED = b'''import os, subprocess
def clone(repo_url, checkout=None, clone_to_dir=".", no_input=False):
    os.makedirs(clone_to_dir, exist_ok=True)
    kind = repo_url.split("+", 1)[0]
    subprocess.check_output([kind, "clone", "/fixtures/" + kind + "source"], cwd=clone_to_dir)
    env = dict(os.environ, PYTHONPATH="/work/shadow")
    subprocess.run([kind, "checkout", checkout], cwd=clone_to_dir + "/" + kind + "source", env=env)
'''
WRONG_DIRECTORY = b'''import os, subprocess
def clone(repo_url, checkout=None, clone_to_dir=".", no_input=False):
    os.makedirs(clone_to_dir, exist_ok=True)
    kind = repo_url.split("+", 1)[0]
    subprocess.check_output([kind, "clone", "/fixtures/" + kind + "source"], cwd=clone_to_dir)
    subprocess.check_output([kind, "clone", "/fixtures/" + kind + "source", "/tmp/other"])
    subprocess.check_output([kind, "checkout", *(["--"] if kind == "hg" else []), checkout], cwd="/tmp/other")
    open(clone_to_dir + "/" + kind + "source/.hg/branch", "w").write(checkout + "\\n")
'''


def tree_hash(root):
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8") + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii")


def cli(arguments, log):
    command = [sys.executable, "-I", "-m", "paladin.cli", "cases", *map(str, arguments), "--json"]
    process = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                             errors="replace", timeout=3600, cwd=ROOT)
    log.write_text(process.stderr, encoding="utf-8")
    return process.returncode, json.loads(process.stdout)


def evaluate_subjects(evidence, workspace):
    from paladin.candidate_scan import scan_project
    results = []
    for name, root, role, expected in SUBJECTS:
        before_hash = tree_hash(root)
        code, auto = cli(["auto", "--project", root, "--workspace", workspace],
                         evidence / (name + ".auto.stderr.txt"))
        write(evidence / (name + ".auto.json"), auto)
        promoted = [run for run in auto.get("case_runs", []) if run["status"] == "promoted"]
        reuse = None
        if promoted:
            reuse_code, reuse = cli(["auto", "--project", root, "--workspace", workspace],
                                    evidence / (name + ".reuse.stderr.txt"))
            write(evidence / (name + ".reuse.json"), reuse)
        after_hash = tree_hash(root)
        results.append({
            "subject": name, "role": role, "expected_candidates": expected,
            "candidates": len(scan_project(root)["candidates"]), "scan_status": auto.get("status"),
            "auto_exit_code": code,
            "case_runs": [{key: run.get(key) for key in ("status", "reason", "checks", "evidence_sha256")}
                          for run in auto.get("case_runs", [])],
            "reused": [run.get("reused") is True for run in (reuse or {}).get("case_runs", [])],
            "source_tree_sha256_before": before_hash, "source_tree_sha256_after": after_hash,
            "source_unchanged": before_hash == after_hash})
    code, listed = cli(["list", "--workspace", workspace], evidence / "list.stderr.txt")
    write(evidence / "list.json", listed)
    return results, listed


def adversarial(evidence, image_id):
    from paladin.case_verification import _repair_bytes, derive_checks, probe_cases
    from paladin.sandbox_runtime import run_observed
    real_before = COOKIECUTTER_VCS.read_bytes()
    real_after = _repair_bytes(real_before, "CVE-2022-24065:mercurial-checkout-v1")
    cookie = probe_cases("cookiecutter")
    observed = {}

    def observe(label, source, adapter="cookiecutter"):
        observed[label] = run_observed(source, image_id, probe_cases(adapter),
                                       evidence / "adversarial" / label, adapter=adapter)
        return observed[label]

    reference_after = observe("cookiecutter-repaired", real_after)
    controls = {
        "masquerade_git_as_hg_before": derive_checks(observe("masquerade", MASQUERADE),
                                                     reference_after, "cookiecutter"),
        "checkout_outside_clone_after": derive_checks(observe("cookiecutter-before", real_before),
                                                      observe("wrong-directory", WRONG_DIRECTORY),
                                                      "cookiecutter"),
        "env_injected_before": derive_checks(observe("env-injected", ENV_INJECTED),
                                             reference_after, "cookiecutter"),
        "pip_23_3_attached_revision_after": derive_checks(
            observe("pip-before", PIP_AFFECTED.read_bytes(), "pip-mercurial"),
            observe("pip-23.3-upstream", PIP_UPSTREAM_FIX.read_bytes(), "pip-mercurial"),
            "pip-mercurial"),
    }
    expectations = {
        "masquerade_git_as_hg_before": ("before_risk_observed", False),
        "checkout_outside_clone_after": ("safe_after_passed", False),
        "pip_23_3_attached_revision_after": ("safe_after_passed", False),
        "env_injected_before": ("before_risk_observed", False),
    }
    summary = {label: {"checks": checks, "expected": {expectations[label][0]: expectations[label][1]},
                       "passed": checks[expectations[label][0]] is expectations[label][1]}
               for label, checks in controls.items()}
    # Every non-risk row records the observer's root replay of its checkout argv.
    summary["replay_rows"] = {label: [[row["role"], row["replayed_argv"], row["replay_branch"]]
                                      for row in output["observations"]]
                              for label, output in observed.items()}
    summary["case_count"] = len(cookie)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-boundary", action="store_true")
    parser.add_argument("--skip-adversarial", action="store_true")
    args = parser.parse_args(argv)
    from paladin.case_runtime import load_runtime
    from paladin.sandbox_runtime import run_boundary_checks
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence = ROOT / "docs" / "evidence" / "private-alpha" / "eval-v4" / ("run-" + stamp)
    evidence.mkdir(parents=True)
    runtime = load_runtime(ROOT)
    workspace = ROOT / ".validation-cache" / "private-alpha-eval" / ("ws-" + stamp)
    (workspace / ".paladin").mkdir(parents=True)
    shutil.copyfile(ROOT / ".paladin" / "runtime.json", workspace / ".paladin" / "runtime.json")
    report = {"status": "IN_PROGRESS", "runtime": runtime, "workspace": str(workspace),
              "python": sys.version.split()[0], "platform": os.name}
    write(evidence / "report.json", report)
    try:
        if not args.skip_boundary:
            boundary = run_boundary_checks(runtime["image_id"], evidence / "boundary")
            write(evidence / "boundary.json", boundary)
            report["boundary"] = {key: boundary[key] for key in ("passed", "executed_controls",
                                                                 "forged_output_ignored")}
        report["subjects"], listed = evaluate_subjects(evidence, workspace)
        report["listed_cases"] = listed.get("cases", [])
        report["list_status"] = listed.get("status")
        if not args.skip_adversarial:
            report["adversarial"] = adversarial(evidence, runtime["image_id"])
        subjects_ok = all(
            item["source_unchanged"] and item["candidates"] == item["expected_candidates"]
            and all(run["status"] == "promoted" for run in item["case_runs"])
            and len(item["case_runs"]) == item["expected_candidates"]
            and all(item["reused"]) and len(item["reused"]) == item["expected_candidates"]
            for item in report["subjects"])
        report["status"] = "PASS" if (subjects_ok
                                      and report.get("boundary", {"passed": True})["passed"]
                                      and all(item["passed"] for key, item in report.get("adversarial", {}).items()
                                              if key not in ("case_count", "replay_rows"))
                                      and len(report["listed_cases"]) == 2) else "FAIL"
    except Exception as exc:
        report["status"] = "ERROR"
        report["error"] = type(exc).__name__ + ": " + str(exc)[:2000]
    leaked = subprocess.run(["docker", "ps", "-a", "--filter", "name=paladin-observer-", "-q"],
                            capture_output=True, text=True, timeout=60).stdout.split()
    report["leaked_observer_containers"] = len(leaked)
    if leaked and report["status"] == "PASS":
        report["status"] = "FAIL"
    write(evidence / "report.json", report)
    print(json.dumps({"status": report["status"], "evidence": str(evidence)}, indent=2))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
