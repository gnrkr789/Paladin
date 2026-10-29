"""Retrospective replay with pinned import surfaces and input manifests."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

if __name__ == "__main__":
    if (sys.pycache_prefix is None or not sys.dont_write_bytecode
            or any(Path(sys.pycache_prefix).rglob("*"))):
        raise RuntimeError("run with -B -X pycache_prefix=<empty-directory>")

from eval.guidance_agent_eval import assess_attempt
from scripts import replay_guidance_worker_eval as prior
from scripts.run_guidance_agent_eval import (CASES, FAMILIES, PROBE, PY39, PY311,
                                             ROOT, install_root, verify_probe)


EVIDENCE = ROOT / "docs/evidence/guidance-agent-worker-replay-v5"
FREEZE = EVIDENCE / "freeze.json"
PROJECT_CODE = {"eval": ROOT / "eval", "scripts": ROOT / "scripts",
                "paladin": ROOT / "src/paladin"}
RUNTIMES = {
    "3.9": PY39.parent,
    "3.11": PY311.parent,
    "3.9.20": install_root("ssrf", "3.9.20"),
}


def is_reparse(path):
    path = Path(path)
    junction_check = getattr(os.path, "isjunction", lambda value: False)
    if path.is_symlink() or junction_check(path):
        return True
    flags = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
    return bool(flags & 0x400)


def strict_manifest(root):
    root = Path(root)
    if not root.is_dir():
        raise FileNotFoundError(root)
    for ancestor in (root, *root.parents):
        if is_reparse(ancestor):
            raise ValueError("reparse ancestor: " + str(ancestor))
    resolved = root.resolve(strict=True)
    files = {}
    for path in sorted(root.rglob("*")):
        if is_reparse(path):
            raise ValueError("reparse entry: " + str(path))
        path.resolve(strict=True).relative_to(resolved)
        if path.is_file():
            files[path.relative_to(root).as_posix()] = prior.digest(path)
    if not files:
        raise ValueError("empty input tree: " + str(root))
    return files


def capture_launch(command, cwd, environment):
    try:
        result = subprocess.run(command, cwd=cwd, env=environment,
                                capture_output=True, timeout=90, check=False)
        return {"command": [str(item) for item in command],
                "exit_code": result.returncode, "stdout": result.stdout,
                "stderr": result.stderr, "timed_out": False, "launch_error": None}
    except subprocess.TimeoutExpired as error:
        return {"command": [str(item) for item in command],
                "exit_code": None, "stdout": error.stdout or b"",
                "stderr": error.stderr or b"", "timed_out": True,
                "launch_error": None}
    except OSError as error:
        return {"command": [str(item) for item in command],
                "exit_code": None, "stdout": b"", "stderr": b"",
                "timed_out": False,
                "launch_error": type(error).__name__ + ": " + str(error)}


def decode_probe(raw):
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("probe output must be a JSON object")
    return value


def validate_attempts(actual, expected):
    if actual != expected or len(set(actual)) != len(actual):
        raise ValueError("attempt list changed")


def freeze():
    if EVIDENCE.exists():
        raise FileExistsError(EVIDENCE)
    prior_frozen = json.loads(prior.FREEZE.read_text(encoding="ascii"))
    prior.verify(prior_frozen)
    for key, expected in prior_frozen["oracle_tree_sha256"].items():
        if strict_manifest(prior.ORACLES / key) != expected:
            raise ValueError("oracle tree differs from earlier replay: " + key)
    if strict_manifest(prior.COMPAT) != prior_frozen["compat_tree_sha256"]:
        raise ValueError("compatibility tree differs from earlier replay")
    targets = {name: str(path.resolve(strict=True)) for name, path in RUNTIMES.items()}
    manifests = {name: strict_manifest(Path(target)) for name, target in targets.items()}
    project_roots = {name: str(path.resolve(strict=True))
                     for name, path in PROJECT_CODE.items()}
    project_manifests = {name: strict_manifest(path) for name, path in PROJECT_CODE.items()}
    frozen = {
        "version": 5, "kind": "retrospective_replay_not_pre_agent_freeze",
        "prior_freeze_sha256": prior.digest(prior.FREEZE),
        "v4_freeze_sha256": prior.digest(ROOT / "docs/evidence/guidance-agent-worker-replay-v4/freeze.json"),
        "self_sha256": prior.digest(Path(__file__)),
        "project_code_roots": project_roots,
        "project_code_tree_sha256": project_manifests,
        "oracle_resolved_roots": {key: str((prior.ORACLES / key).resolve(strict=True))
                                  for key in prior_frozen["attempts"]},
        "runtime_alias_targets": targets,
        "runtime_tree_sha256": manifests,
        "attempts": prior_frozen["attempts"],
        "limitations": [
            "The original worker prompts, edits and trace status are unchanged.",
            "This version was frozen after worker edits and earlier replays.",
            "No operating-system security sandbox or network isolation is provided.",
        ],
    }
    prior.write_json(FREEZE, frozen)
    print(json.dumps({"status": "FROZEN", "attempts": len(frozen["attempts"]),
                      "runtime_files": sum(len(tree) for tree in manifests.values()),
                      "project_code_files": sum(len(tree) for tree in project_manifests.values())}))


def verify(frozen):
    if prior.digest(Path(__file__)) != frozen["self_sha256"]:
        raise ValueError("replay implementation changed")
    if prior.digest(prior.FREEZE) != frozen["prior_freeze_sha256"]:
        raise ValueError("earlier replay freeze changed")
    if prior.digest(ROOT / "docs/evidence/guidance-agent-worker-replay-v4/freeze.json") != frozen["v4_freeze_sha256"]:
        raise ValueError("v4 replay freeze changed")
    prior_frozen = json.loads(prior.FREEZE.read_text(encoding="ascii"))
    validate_attempts(frozen["attempts"], prior_frozen["attempts"])
    prior.verify(prior_frozen)
    for key, expected in prior_frozen["oracle_tree_sha256"].items():
        if str((prior.ORACLES / key).resolve(strict=True)) != frozen["oracle_resolved_roots"][key]:
            raise ValueError("oracle root moved: " + key)
        if strict_manifest(prior.ORACLES / key) != expected:
            raise ValueError("reparse or changed oracle tree: " + key)
    if strict_manifest(prior.COMPAT) != prior_frozen["compat_tree_sha256"]:
        raise ValueError("reparse or changed compatibility tree")
    for name, path in PROJECT_CODE.items():
        if str(path.resolve(strict=True)) != frozen["project_code_roots"][name]:
            raise ValueError("project code root moved: " + name)
        if strict_manifest(path) != frozen["project_code_tree_sha256"][name]:
            raise ValueError("project code changed: " + name)
    for name, path in RUNTIMES.items():
        target = str(path.resolve(strict=True))
        if target != frozen["runtime_alias_targets"][name]:
            raise ValueError("runtime alias target changed: " + name)
        if strict_manifest(Path(target)) != frozen["runtime_tree_sha256"][name]:
            raise ValueError("runtime files changed: " + name)


def verify_attempt(frozen, key):
    if prior.digest(prior.FREEZE) != frozen["prior_freeze_sha256"]:
        raise ValueError("earlier replay freeze changed")
    prior_frozen = json.loads(prior.FREEZE.read_text(encoding="ascii"))
    if key not in frozen["attempts"] or frozen["attempts"] != prior_frozen["attempts"]:
        raise ValueError("attempt policy changed")
    if prior.digest(Path(__file__)) != frozen["self_sha256"]:
        raise ValueError("replay implementation changed")
    for name, expected in prior_frozen["code_sha256"].items():
        if prior.digest(ROOT / name) != expected:
            raise ValueError("scorer code changed: " + name)
    if (prior.digest(prior.PRIMARY / "runs" / key / "run.json")
            != prior_frozen["primary_run_sha256"][key]):
        raise ValueError("primary run changed: " + key)
    root = prior.ORACLES / key
    if str(root.resolve(strict=True)) != frozen["oracle_resolved_roots"][key]:
        raise ValueError("oracle root moved: " + key)
    if strict_manifest(root) != prior_frozen["oracle_tree_sha256"][key]:
        raise ValueError("oracle changed: " + key)
    if strict_manifest(prior.COMPAT) != prior_frozen["compat_tree_sha256"]:
        raise ValueError("compatibility package changed")
    for name, path in PROJECT_CODE.items():
        if str(path.resolve(strict=True)) != frozen["project_code_roots"][name]:
            raise ValueError("project code root moved: " + name)
        if strict_manifest(path) != frozen["project_code_tree_sha256"][name]:
            raise ValueError("project code changed: " + name)
    for name, alias in RUNTIMES.items():
        target = str(alias.resolve(strict=True))
        if target != frozen["runtime_alias_targets"][name]:
            raise ValueError("runtime alias moved: " + name)
        if strict_manifest(Path(target)) != frozen["runtime_tree_sha256"][name]:
            raise ValueError("runtime changed: " + name)


def command_for(key):
    family = key.split("-", 1)[1]
    spec = FAMILIES[family]
    python = (RUNTIMES["3.9.20"] / "python.exe" if spec["package"] == "cpython"
              else PY311 if spec["package"] == "bentoml" else PY39)
    command = [str(python), "-B", str(PROBE), "--cases", str(CASES), "--family", family]
    if spec["package"] != "cpython":
        command += ["--target", str(prior.ORACLES / key)]
    if spec["package"] == "bentoml":
        command += ["--compat", str(prior.COMPAT)]
    return command


def replay():
    frozen = json.loads(FREEZE.read_text(encoding="ascii"))
    verify(frozen)
    cases = json.loads(CASES.read_text(encoding="ascii"))["cases"]
    rows = []
    for key in frozen["attempts"]:
        verify_attempt(frozen, key)
        family = key.split("-", 1)[1]
        spec = FAMILIES[family]
        result_dir = EVIDENCE / "runs" / key
        if result_dir.exists():
            raise FileExistsError(result_dir)
        original = json.loads((prior.PRIMARY / "runs" / key / "run.json").read_text(encoding="ascii"))
        captured = capture_launch(command_for(key), ROOT, prior.environment_for(family, key))
        result_dir.mkdir(parents=True, exist_ok=False)
        (result_dir / "stdout.bin").write_bytes(captured.pop("stdout"))
        (result_dir / "stderr.bin").write_bytes(captured.pop("stderr"))
        captured["stdout_sha256"] = prior.digest(result_dir / "stdout.bin")
        captured["stderr_sha256"] = prior.digest(result_dir / "stderr.bin")
        output, assessments, diagnostic = None, None, None
        if captured["exit_code"] == 0:
            try:
                output = decode_probe((result_dir / "stdout.bin").read_bytes())
                assessments = verify_probe(
                    output, family, spec["vulnerable"], prior.source_path(key),
                    [case for case in cases if case["family"] == family], "fixed")
            except (ValueError, KeyError, AssertionError, TypeError, AttributeError) as error:
                diagnostic = type(error).__name__ + ": " + str(error)
        elif captured["launch_error"]:
            diagnostic = captured["launch_error"]
        elif captured["timed_out"]:
            diagnostic = "probe timed out"
        else:
            diagnostic = "probe exited without a scored outcome"
        status = assess_attempt(
            0 if original["worker_completed"] else 1,
            bool(original["changed_files"]), bool(original["unexpected_files"]),
            assessments)
        record = {"key": key, "status": status, "process": captured,
                  "expected_source_file": str(prior.source_path(key).resolve()),
                  "loaded_source_file": output.get("source_file") if isinstance(output, dict) else None,
                  "source_sha256": prior.digest(prior.source_path(key)),
                  "oracle": output, "assessments": assessments,
                  "diagnostic": diagnostic}
        prior.write_json(result_dir / "run.json", record)
        rows.append({"key": key, "primary_status": original["status"],
                     "replay_status": status, "exit_code": captured["exit_code"]})
        if strict_manifest(prior.ORACLES / key) != json.loads(prior.FREEZE.read_text(
                encoding="ascii"))["oracle_tree_sha256"][key]:
            raise ValueError("oracle tree changed during replay: " + key)
    verify(frozen)
    summary = {"kind": "retrospective_replay", "freeze_sha256": prior.digest(FREEZE),
               "rows": rows, "same_primary_status": all(
                   row["primary_status"] == row["replay_status"] for row in rows)}
    prior.write_json(EVIDENCE / "summary.json", summary)
    print(json.dumps({"status": "COMPLETE", "same_primary_status": summary["same_primary_status"],
                      "rows": len(rows)}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("freeze", "verify", "replay"))
    args = parser.parse_args()
    if args.action == "freeze":
        freeze()
    elif args.action == "verify":
        verify(json.loads(FREEZE.read_text(encoding="ascii")))
        print("REPLAY_V3_INPUT_IDENTITY_OK")
    else:
        replay()


if __name__ == "__main__":
    main()
