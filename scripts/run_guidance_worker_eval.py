"""Freeze and score isolated coding-worker repairs with a private oracle."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil

from eval.guidance_agent_eval import assess_attempt
from scripts.run_guidance_agent_eval import (CASES, CACHE, FAMILIES, PROBE, ROOT,
                                             TASKS as CLI_TASKS, install_root,
                                             run_probe, sha, verify_probe, write_json)


EVIDENCE = ROOT / "docs/evidence/guidance-agent-worker-eval"
FREEZE = EVIDENCE / "freeze.json"
TASKS = CACHE / "agent-worker-eval/tasks"
ORACLES = CACHE / "agent-worker-eval/oracles"


def prepare():
    if FREEZE.exists() or TASKS.exists():
        raise FileExistsError("worker evaluation already prepared")
    source_hashes = {}
    prompt_hashes = {}
    for family, spec in FAMILIES.items():
        for arm in ("A", "C"):
            key = arm + "-" + family
            shutil.copytree(CLI_TASKS / key, TASKS / key)
            prompt_hashes[key] = sha(TASKS / key / "prompt.txt")
            source_hashes[key] = {relative: sha(TASKS / key / relative)
                                  for relative in spec["files"]}
    freeze = {"version": 1, "scope": "isolated_collaboration_worker_agent_repair",
              "cases_sha256": sha(CASES), "probe_sha256": sha(PROBE),
              "guidance_sha256": sha(ROOT / "src/paladin/resources/guidance-pack.json"),
              "agent_model": "gpt-6.1-sol", "agent_effort": "medium",
              "attempts": [arm + "-" + family for family in FAMILIES for arm in ("A", "C")],
              "source_hashes": source_hashes, "prompt_hashes": prompt_hashes,
              "limitations": ["One attempt per family and arm; descriptive evidence only.",
                              "Worker tool traces are not included in this local artifact."]}
    write_json(FREEZE, freeze)
    print(json.dumps({"status": "FROZEN", "attempts": len(freeze["attempts"]),
                      "freeze": str(FREEZE)}))


def load_freeze():
    freeze = json.loads(FREEZE.read_text(encoding="ascii"))
    for path, name in ((CASES, "cases_sha256"), (PROBE, "probe_sha256"),
                       (ROOT / "src/paladin/resources/guidance-pack.json", "guidance_sha256")):
        if sha(path) != freeze[name]:
            raise ValueError(f"frozen input changed: {path}")
    for key, expected in freeze["prompt_hashes"].items():
        if sha(TASKS / key / "prompt.txt") != expected:
            raise ValueError(f"frozen prompt changed: {key}")
    return freeze


def oracle_for(key, task, family, cases):
    spec = FAMILIES[family]
    version = spec["vulnerable"]
    destination = ORACLES / key
    if destination.exists():
        raise FileExistsError("oracle directory exists")
    if spec["package"] == "cpython":
        overlay = destination / "overlay"
        shutil.copytree(install_root(family, version) / "Lib/urllib", overlay / "urllib")
        shutil.copy2(task / "urllib/parse.py", overlay / "urllib/parse.py")
        source, target = overlay / spec["source"], None
    else:
        shutil.copytree(install_root(family, version), destination)
        for relative in spec["files"]:
            shutil.copy2(task / relative, destination / relative)
        source, target, overlay = destination / spec["source"], destination, None
    try:
        output = run_probe(family, version, target=target, overlay=overlay)
        return output, verify_probe(output, family, version, source, cases, "fixed"), None
    except Exception as error:
        return None, None, repr(error)[-1500:]


def score(key, worker_id, completed):
    freeze = load_freeze()
    if key not in freeze["attempts"]:
        raise ValueError("unknown attempt")
    arm, family = key.split("-", 1)
    spec = FAMILIES[family]
    task = TASKS / key
    output_dir = EVIDENCE / "runs" / key
    output_dir.mkdir(parents=True, exist_ok=False)
    before = freeze["source_hashes"][key]
    after = {relative: sha(task / relative) for relative in spec["files"]}
    changed = [relative for relative in spec["files"] if before[relative] != after[relative]]
    expected_files = set(spec["files"]) | {"AGENTS.md", "prompt.txt"}
    current_files = {path.relative_to(task).as_posix() for path in task.rglob("*") if path.is_file()}
    generated = sorted(path for path in current_files - expected_files
                       if "__pycache__" in Path(path).parts or path.endswith(".pyc"))
    unexpected = sorted((current_files - expected_files) - set(generated))
    if sha(task / "AGENTS.md") != sha(CLI_TASKS / key / "AGENTS.md"):
        unexpected.append("modified AGENTS.md")
    cases = [case for case in json.loads(CASES.read_text(encoding="ascii"))["cases"]
             if case["family"] == family]
    oracle, assessments, error = (oracle_for(key, task, family, cases)
                                  if changed and not unexpected else (None, None, None))
    status = assess_attempt(0 if completed else 1, bool(changed), bool(unexpected), assessments)
    for relative in spec["files"]:
        destination = output_dir / "source.after" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(task / relative, destination)
    result = {"key": key, "arm": arm, "family": family, "worker_id": worker_id,
              "worker_completed": completed, "status": status, "changed_files": changed,
              "unexpected_files": unexpected, "generated_files": generated,
              "before_sha256": before, "after_sha256": after,
              "oracle": oracle, "assessments": assessments, "oracle_error": error,
              "frozen_inputs_unchanged": bool(load_freeze())}
    write_json(output_dir / "run.json", result)
    print(json.dumps({"key": key, "status": status, "changed": len(changed),
                      "private_passed": sum(item["pass"] for item in assessments or [])}))


def report():
    freeze = load_freeze()
    rows = []
    for key in freeze["attempts"]:
        path = EVIDENCE / "runs" / key / "run.json"
        rows.append(json.loads(path.read_text(encoding="ascii")) if path.exists()
                    else {"key": key, "arm": key[0], "family": key[2:], "status": "not_run"})
    arms = {arm: {status: sum(row["arm"] == arm and row["status"] == status for row in rows)
                  for status in ("success", "failed", "incomplete", "not_run")}
            for arm in ("A", "C")}
    summary = {"status": "COMPLETE" if all(row["status"] != "not_run" for row in rows) else "PARTIAL",
               "scope": "five_correlated_upstream_tasks_one_worker_per_arm",
               "freeze_sha256": sha(FREEZE), "cases_sha256": freeze["cases_sha256"],
               "arms": arms, "rows": [{field: row.get(field) for field in
                                      ("key", "arm", "family", "status", "worker_id")}
                                      for row in rows],
               "limitations": ["No broad or causal effectiveness claim from five cases per arm.",
                               "Boundary oracle only; no full upstream test suite or exploit run.",
                               "Worker tool traces are not included in local evidence.",
                               "Candidate guidance remains unreviewed and unpromoted."]}
    write_json(EVIDENCE / "summary.json", summary)
    print(json.dumps({"status": summary["status"], "arms": arms}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("prepare", "score", "report"))
    parser.add_argument("--key")
    parser.add_argument("--worker-id")
    parser.add_argument("--completed", action="store_true")
    args = parser.parse_args()
    if args.action == "prepare":
        prepare()
    elif args.action == "score":
        if not args.key or not args.worker_id:
            raise ValueError("score requires --key and --worker-id")
        score(args.key, args.worker_id, args.completed)
    else:
        report()


if __name__ == "__main__":
    main()
