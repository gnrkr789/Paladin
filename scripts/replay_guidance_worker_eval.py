"""Freeze and replay preserved worker patches without changing primary scores."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

from eval.guidance_agent_eval import assess_attempt
from scripts.run_guidance_agent_eval import (CASES, CACHE, FAMILIES, PROBE, PY39,
                                             PY311, ROOT, install_root, verify_probe)


EVIDENCE = ROOT / "docs/evidence/guidance-agent-worker-replay-v2"
FREEZE = EVIDENCE / "freeze.json"
PRIMARY = ROOT / "docs/evidence/guidance-agent-worker-eval"
ORACLES = CACHE / "agent-worker-eval/oracles"
COMPAT = CACHE / "upstream/legacy-bento-deps"
CODE_FILES = (
    "eval/guidance_agent_cases.json",
    "eval/guidance_holdout_probe.py",
    "eval/guidance_agent_eval.py",
    "scripts/run_guidance_agent_eval.py",
    "scripts/run_guidance_worker_eval.py",
    "scripts/replay_guidance_worker_eval.py",
    "src/paladin/resources/guidance-pack.json",
)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def manifest_tree(root):
    root = Path(root)
    if not root.is_dir():
        raise FileNotFoundError(root)
    manifest = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("symlink in replay input: " + str(path))
        if path.is_file():
            manifest[path.relative_to(root).as_posix()] = digest(path)
    if not manifest:
        raise ValueError("empty replay input: " + str(root))
    return manifest


def verify_tree(root, expected):
    if manifest_tree(root) != expected:
        raise ValueError("replay input tree changed: " + str(root))


def capture_process(command, cwd, environment):
    try:
        result = subprocess.run(command, cwd=cwd, env=environment,
                                capture_output=True, timeout=90, check=False)
        return {"command": [str(item) for item in command],
                "exit_code": result.returncode, "stdout": result.stdout,
                "stderr": result.stderr, "timed_out": False}
    except subprocess.TimeoutExpired as error:
        return {"command": [str(item) for item in command], "exit_code": None,
                "stdout": error.stdout or b"", "stderr": error.stderr or b"",
                "timed_out": True}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="ascii", newline="\n") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=True, sort_keys=True)
        stream.write("\n")


def keys():
    return [arm + "-" + family for family in FAMILIES for arm in ("A", "C")]


def source_path(key):
    family = key.split("-", 1)[1]
    spec = FAMILIES[family]
    prefix = "overlay/" if spec["package"] == "cpython" else ""
    return ORACLES / key / (prefix + spec["source"])


def assert_patch_identity(key, expected_source):
    family = key.split("-", 1)[1]
    spec = FAMILIES[family]
    primary_run = json.loads((PRIMARY / "runs" / key / "run.json").read_text(encoding="ascii"))
    for relative in spec["files"]:
        expected = primary_run["after_sha256"][relative]
        archived = PRIMARY / "runs" / key / "source.after" / relative
        if digest(archived) != expected:
            raise ValueError("archived patch changed: " + key + ":" + relative)
        installed = ORACLES / key / (("overlay/" if spec["package"] == "cpython" else "") + relative)
        if digest(installed) != expected:
            raise ValueError("oracle patch changed: " + key + ":" + relative)
    if digest(source_path(key)) != expected_source:
        raise ValueError("loaded source changed: " + key)
    return primary_run


def freeze():
    if FREEZE.exists() or EVIDENCE.exists():
        raise FileExistsError(EVIDENCE)
    code_hashes = {name: digest(ROOT / name) for name in CODE_FILES}
    run_hashes = {}
    tree_hashes = {}
    for key in keys():
        family = key.split("-", 1)[1]
        spec = FAMILIES[family]
        run_file = PRIMARY / "runs" / key / "run.json"
        run_hashes[key] = digest(run_file)
        expected = json.loads(run_file.read_text(encoding="ascii"))["after_sha256"][spec["source"]]
        assert_patch_identity(key, expected)
        tree_hashes[key] = manifest_tree(ORACLES / key)
    frozen = {
        "version": 2, "kind": "retrospective_replay_not_pre_agent_freeze",
        "primary_freeze_sha256": digest(PRIMARY / "freeze.json"),
        "primary_summary_sha256": digest(PRIMARY / "summary.json"),
        "code_sha256": code_hashes, "primary_run_sha256": run_hashes,
        "oracle_tree_sha256": tree_hashes,
        "compat_tree_sha256": manifest_tree(COMPAT),
        "python_sha256": {
            "3.9": digest(PY39), "3.11": digest(PY311),
            "3.9.20": digest(install_root("ssrf", "3.9.20") / "python.exe"),
        },
        "attempts": keys(),
        "limitations": [
            "This replay was frozen after worker edits and cannot repair the original freeze.",
            "The original worker tool traces and failed subprocess stderr cannot be recovered.",
            "File manifests provide identity, not process security isolation.",
        ],
    }
    write_json(FREEZE, frozen)
    print(json.dumps({"status": "FROZEN", "attempts": len(keys()),
                      "files": sum(len(tree) for tree in tree_hashes.values())}))


def verify(frozen):
    if frozen["attempts"] != keys():
        raise ValueError("family or arm policy changed")
    for name, expected in frozen["code_sha256"].items():
        if digest(ROOT / name) != expected:
            raise ValueError("scorer or input code changed: " + name)
    if digest(PRIMARY / "freeze.json") != frozen["primary_freeze_sha256"]:
        raise ValueError("primary freeze changed")
    if digest(PRIMARY / "summary.json") != frozen["primary_summary_sha256"]:
        raise ValueError("primary summary changed")
    for key, expected in frozen["primary_run_sha256"].items():
        if digest(PRIMARY / "runs" / key / "run.json") != expected:
            raise ValueError("primary result changed: " + key)
        family = key.split("-", 1)[1]
        source = FAMILIES[family]["source"]
        assert_patch_identity(key, frozen["oracle_tree_sha256"][key][
            ("overlay/" if FAMILIES[family]["package"] == "cpython" else "") + source])
        verify_tree(ORACLES / key, frozen["oracle_tree_sha256"][key])
    verify_tree(COMPAT, frozen["compat_tree_sha256"])
    if (digest(PY39) != frozen["python_sha256"]["3.9"]
            or digest(PY311) != frozen["python_sha256"]["3.11"]
            or digest(install_root("ssrf", "3.9.20") / "python.exe")
            != frozen["python_sha256"]["3.9.20"]):
        raise ValueError("Python runtime changed")


def environment_for(family, key):
    allowed = ("SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP", "COMSPEC")
    environment = {name: os.environ[name] for name in allowed if name in os.environ}
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    if FAMILIES[family]["package"] == "cpython":
        environment["PYTHONPATH"] = str(ORACLES / key / "overlay")
    return environment


def replay():
    frozen = json.loads(FREEZE.read_text(encoding="ascii"))
    verify(frozen)
    cases = json.loads(CASES.read_text(encoding="ascii"))["cases"]
    rows = []
    for key in frozen["attempts"]:
        family = key.split("-", 1)[1]
        spec = FAMILIES[family]
        primary_run = json.loads((PRIMARY / "runs" / key / "run.json").read_text(encoding="ascii"))
        result_dir = EVIDENCE / "runs" / key
        if result_dir.exists():
            raise FileExistsError(result_dir)
        target = ORACLES / key
        python = (install_root(family, spec["vulnerable"]) / "python.exe"
                  if spec["package"] == "cpython" else PY311 if spec["package"] == "bentoml" else PY39)
        command = [str(python), "-B", str(PROBE), "--cases", str(CASES), "--family", family]
        if spec["package"] != "cpython":
            command += ["--target", str(target)]
        if spec["package"] == "bentoml":
            command += ["--compat", str(COMPAT)]
        captured = capture_process(command, ROOT, environment_for(family, key))
        result_dir.mkdir(parents=True, exist_ok=False)
        (result_dir / "stdout.bin").write_bytes(captured.pop("stdout"))
        (result_dir / "stderr.bin").write_bytes(captured.pop("stderr"))
        captured["stdout_sha256"] = digest(result_dir / "stdout.bin")
        captured["stderr_sha256"] = digest(result_dir / "stderr.bin")
        output, assessments, diagnostic = None, None, None
        if captured["exit_code"] == 0:
            try:
                output = json.loads((result_dir / "stdout.bin").read_text(encoding="utf-8"))
                assessments = verify_probe(
                    output, family, spec["vulnerable"], source_path(key),
                    [case for case in cases if case["family"] == family], "fixed")
            except (ValueError, KeyError, AssertionError) as error:
                diagnostic = type(error).__name__ + ": " + str(error)
        else:
            diagnostic = "probe exited without a scored outcome"
        status = assess_attempt(
            0 if primary_run["worker_completed"] else 1,
            bool(primary_run["changed_files"]), bool(primary_run["unexpected_files"]),
            assessments)
        record = {"key": key, "status": status, "process": captured,
                  "source_file": str(source_path(key).resolve()),
                  "source_sha256": digest(source_path(key)),
                  "oracle": output, "assessments": assessments,
                  "diagnostic": diagnostic}
        write_json(result_dir / "run.json", record)
        rows.append({"key": key, "primary_status": primary_run["status"],
                     "replay_status": status, "exit_code": captured["exit_code"]})
        verify(frozen)
    summary = {"kind": "retrospective_replay", "freeze_sha256": digest(FREEZE),
               "rows": rows, "same_primary_status": all(
                   row["primary_status"] == row["replay_status"] for row in rows)}
    write_json(EVIDENCE / "summary.json", summary)
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
        print("REPLAY_INPUT_IDENTITY_OK")
    else:
        replay()


if __name__ == "__main__":
    main()
