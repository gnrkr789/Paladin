"""Run a five-family, two-arm candidate guidance patch evaluation."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import time
import tomllib

from eval.guidance_agent_eval import assess_attempt
from paladin.guidance import checked_claim, load_guidance
from paladin.knowledge import load_pack


ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".validation-cache"
TASKS = CACHE / "agent-eval/tasks"
ORACLES = CACHE / "agent-eval/oracles"
EVIDENCE = ROOT / "docs/evidence/guidance-agent-eval"
FREEZE = EVIDENCE / "freeze.json"
CASES = ROOT / "eval/guidance_agent_cases.json"
PROBE = ROOT / "eval/guidance_holdout_probe.py"
PY39 = Path("C:/Users/user/AppData/Roaming/uv/python/cpython-3.9-windows-x86_64-none/python.exe")
PY311 = Path("C:/Users/user/AppData/Roaming/uv/python/cpython-3.11-windows-x86_64-none/python.exe")
CODEX = (Path("C:/Users/user/AppData/Roaming/npm/node_modules/@openai/codex/node_modules")
         / "@openai/codex-win32-x64/vendor/x86_64-pc-windows-msvc/bin/codex.exe")
CONFIG = Path("C:/Users/user/.codex/config.toml")
TIMEOUT = 180
FAMILIES = {
    "path_traversal": {"package": "django", "vulnerable": "3.2.0", "fixed": "3.2.1",
                       "cve": "CVE-2021-31542", "files": [
                           "django/core/files/storage.py", "django/core/files/uploadedfile.py",
                           "django/core/files/utils.py", "django/db/models/fields/files.py",
                           "django/http/multipartparser.py", "django/utils/text.py"],
                       "source": "django/utils/text.py",
                       "task": "Prevent unsafe upload or storage filenames from reaching a path boundary."},
    "sql_injection": {"package": "django", "vulnerable": "3.2.13", "fixed": "3.2.14",
                      "cve": "CVE-2022-34265", "files": [
                          "django/db/backends/base/operations.py",
                          "django/db/models/functions/datetime.py"],
                      "source": "django/db/models/functions/datetime.py",
                      "task": "Prevent untrusted Trunc kind and Extract lookup_name from changing SQL structure."},
    "ssrf": {"package": "cpython", "vulnerable": "3.9.20", "fixed": "3.9.21",
             "cve": "CVE-2024-11168", "files": ["urllib/parse.py"],
             "source": "urllib/parse.py",
             "task": "Correct bracketed URL host parsing before applications use the parsed host."},
    "command_injection": {"package": "cookiecutter", "vulnerable": "2.1.0", "fixed": "2.1.1",
                          "cve": "CVE-2022-24065", "files": ["cookiecutter/vcs.py"],
                          "source": "cookiecutter/vcs.py",
                          "task": "Prevent an untrusted Mercurial checkout target from being treated as an option."},
    "unsafe_deserialization": {"package": "bentoml", "vulnerable": "1.2.4", "fixed": "1.2.5",
                               "cve": "CVE-2024-2912", "files": ["_bentoml_impl/server/app.py"],
                               "source": "_bentoml_impl/server/app.py",
                               "task": "Stop pickle media-type requests at the main HTTP service boundary."},
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="ascii", newline="\n") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=True, sort_keys=True)
        stream.write("\n")


def install_root(family: str, version: str) -> Path:
    spec = FAMILIES[family]
    if spec["package"] == "cpython":
        return CACHE / "python" / ("cpython-" + version + "-windows-x86_64-none")
    return CACHE / "upstream" / (spec["package"] + "-" + version)


def source_in_install(family: str, version: str, relative: str) -> Path:
    base = install_root(family, version)
    return base / ("Lib/" + relative if FAMILIES[family]["package"] == "cpython" else relative)


def run_probe(family: str, version: str, *, target: Path | None = None,
              overlay: Path | None = None) -> dict:
    spec = FAMILIES[family]
    python = (install_root(family, version) / "python.exe" if spec["package"] == "cpython"
              else PY311 if spec["package"] == "bentoml" else PY39)
    args = [str(python), "-B", str(PROBE), "--cases", str(CASES), "--family", family]
    if spec["package"] != "cpython":
        args += ["--target", str(target or install_root(family, version))]
    if spec["package"] == "bentoml":
        args += ["--compat", str(CACHE / "upstream/legacy-bento-deps")]
    environment = os.environ.copy()
    if overlay:
        environment["PYTHONPATH"] = str(overlay)
    result = subprocess.run(args, cwd=ROOT, env=environment, capture_output=True,
                            text=True, timeout=90, check=True)
    return json.loads(result.stdout)


def verify_probe(output: dict, family: str, version: str, source: Path,
                 cases: list[dict], expected_field: str) -> list[dict]:
    spec = FAMILIES[family]
    assert output["family"] == family
    assert output["package"].lower() == spec["package"]
    assert output["version"] == version
    assert Path(output["source_file"]).resolve() == source.resolve()
    assessments = []
    for case in cases:
        observed = output["outcomes"][case["id"]]
        matched = observed["result"] == case[expected_field]
        if (family == "unsafe_deserialization" and expected_field == "fixed"
                and case["role"] == "risk"):
            matched = matched and observed.get("error_code") == 415
        assessments.append({"id": case["id"], "role": case["role"],
                            "expected": case[expected_field], "observed": observed["result"],
                            "pass": matched})
    return assessments


def task_source(family: str, relative: str) -> Path:
    return source_in_install(family, FAMILIES[family]["vulnerable"], relative)


def card_for(family: str, pack: dict, guidance: dict) -> dict:
    claim = checked_claim(ROOT, FAMILIES[family]["cve"], pack, guidance)
    return {key: claim[key] for key in ("pattern_id", "cause", "target_facts",
                                         "fix_steps", "preserve", "checks", "limitations",
                                         "provenance")}


def prompt_for(family: str, arm: str, card: dict | None) -> str:
    spec = FAMILIES[family]
    allowed = ", ".join(spec["files"])
    base = (f"Repair {spec['cve']} in these vulnerable {spec['package']} {spec['vulnerable']} "
            f"source files. {spec['task']} Preserve ordinary supported behavior. "
            f"Edit only these files: {allowed}. Do not edit AGENTS.md, add files, inspect parent "
            "directories, or read evaluation tests. Run a local check if feasible and report "
            "what you changed and what you checked.\n")
    if arm == "C":
        base += ("Use this Paladin candidate guidance as conditional advice. Verify its "
                 "applicability against the provided source; it is not an approval or a "
                 "test result.\n" + json.dumps(card, ensure_ascii=True, sort_keys=True) + "\n")
    return base


def prepare() -> None:
    if FREEZE.exists():
        raise FileExistsError("evaluation already frozen")
    if any(TASKS.iterdir()) if TASKS.exists() else False:
        raise FileExistsError("task directory is not empty")
    cases = json.loads(CASES.read_text(encoding="ascii"))["cases"]
    if len(cases) != 20 or len({item["id"] for item in cases}) != 20:
        raise ValueError("expected twenty unique private cases")
    pack, guidance = load_pack(), load_guidance()
    preflight = {}
    source_hashes = {}
    prompts = {}
    for family, spec in FAMILIES.items():
        family_cases = [item for item in cases if item["family"] == family]
        if len(family_cases) != 4 or sum(item["role"] == "risk" for item in family_cases) != 2:
            raise ValueError("expected two risk and two safe cases per family")
        preflight[family] = {}
        for label, version in (("vulnerable", spec["vulnerable"]), ("fixed", spec["fixed"])):
            output = run_probe(family, version)
            source = source_in_install(family, version, spec["source"])
            assessments = verify_probe(output, family, version, source, family_cases, label)
            if not all(item["pass"] for item in assessments):
                raise ValueError(f"invalid preflight: {family} {label}: {assessments}")
            preflight[family][label] = {"version": version, "source_file": str(source.resolve()),
                                        "source_sha256": sha(source), "assessments": assessments}
        for relative in spec["files"]:
            source_hashes[family + ":" + relative] = sha(task_source(family, relative))
        card = card_for(family, pack, guidance)
        for arm in ("A", "C"):
            key = arm + "-" + family
            directory = TASKS / key
            directory.mkdir(parents=True)
            (directory / "AGENTS.md").write_text(
                "# Isolated upstream repair task\n\nUse English and edit only the source files named in the prompt.\n"
                "Do not inspect parent directories or evaluation files.\n", encoding="ascii")
            for relative in spec["files"]:
                destination = directory / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(task_source(family, relative), destination)
            prompt = prompt_for(family, arm, card if arm == "C" else None)
            (directory / "prompt.txt").write_text(prompt, encoding="ascii")
            prompts[key] = sha(directory / "prompt.txt")
    config = tomllib.loads(CONFIG.read_text(encoding="utf-8"))
    schedule = [arm + "-" + family for family in FAMILIES for arm in ("A", "C")]
    random.Random(12341).shuffle(schedule)
    freeze = {"version": 1, "scope": "candidate_guidance_agent_patch_evaluation",
              "cases_sha256": sha(CASES), "probe_sha256": sha(PROBE),
              "guidance_sha256": sha(ROOT / "src/paladin/resources/guidance-pack.json"),
              "codex_sha256": sha(CODEX), "config_sha256": sha(CONFIG),
              "model": config["model"], "effort": config["model_reasoning_effort"],
              "host_permission": "workspace-write", "timeout_seconds": TIMEOUT,
              "source_hashes": source_hashes, "prompts": prompts,
              "schedule": schedule, "preflight": preflight,
              "limitations": ["One attempt per family and arm; no causal or population claim.",
                              "Private tests exercise boundaries, not complete upstream suites."]}
    write_json(FREEZE, freeze)
    print(json.dumps({"status": "FROZEN", "attempts": len(schedule),
                      "cases": len(cases), "freeze": str(FREEZE)}))


def load_freeze() -> dict:
    freeze = json.loads(FREEZE.read_text(encoding="ascii"))
    for path, key in ((CASES, "cases_sha256"), (PROBE, "probe_sha256"),
                      (CODEX, "codex_sha256"), (CONFIG, "config_sha256"),
                      (ROOT / "src/paladin/resources/guidance-pack.json", "guidance_sha256")):
        if sha(path) != freeze[key]:
            raise ValueError(f"frozen input changed: {path}")
    for descriptor, expected in freeze["source_hashes"].items():
        family, relative = descriptor.split(":", 1)
        if sha(task_source(family, relative)) != expected:
            raise ValueError(f"vulnerable source changed: {descriptor}")
    for key, expected in freeze["prompts"].items():
        if sha(TASKS / key / "prompt.txt") != expected:
            raise ValueError(f"frozen prompt changed: {key}")
    return freeze


def host_command(task: Path, output: Path, freeze: dict) -> list[str]:
    args = [str(CODEX), "exec", "--ignore-user-config", "--ephemeral",
            "--skip-git-repo-check", "--sandbox", "workspace-write", "--json",
            "--color", "never", "--cd", str(task), "--output-last-message",
            str(output / "final.txt")]
    for key, value in (("model", freeze["model"]),
                       ("model_reasoning_effort", freeze["effort"])):
        args += ["-c", key + "=" + json.dumps(value)]
    return args + ["-"]


def run_host(command: list[str], prompt: str, output: Path) -> dict:
    import win32api
    import win32job

    job = win32job.CreateJobObject(None, "")
    limits = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
    limits["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, limits)
    process = None
    started = time.monotonic()
    result = {"status": "started", "exit_code": None}
    try:
        with (output / "host.jsonl").open("xb") as stdout, (output / "host.stderr.txt").open("xb") as stderr:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=stdout,
                                       stderr=stderr, creationflags=subprocess.CREATE_NO_WINDOW)
            win32job.AssignProcessToJobObject(job, int(process._handle))
            try:
                process.communicate(prompt.encode("ascii"), timeout=TIMEOUT)
                result["exit_code"] = process.returncode
                result["status"] = "finished" if process.returncode == 0 else "host_failed"
            except subprocess.TimeoutExpired:
                win32job.TerminateJobObject(job, 1)
                process.wait(timeout=5)
                result["status"] = "timeout"
    finally:
        win32job.TerminateJobObject(job, 1)
        win32api.CloseHandle(job)
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    result["elapsed_seconds"] = time.monotonic() - started
    return result


def patched_oracle(family: str, key: str, task: Path, cases: list[dict]) -> tuple[dict | None, list[dict] | None, str | None]:
    spec = FAMILIES[family]
    version = spec["vulnerable"]
    destination = ORACLES / key
    if destination.exists():
        raise FileExistsError(f"oracle installation exists: {destination}")
    if spec["package"] == "cpython":
        overlay = destination / "overlay"
        shutil.copytree(install_root(family, version) / "Lib/urllib", overlay / "urllib")
        shutil.copy2(task / "urllib/parse.py", overlay / "urllib/parse.py")
        source = overlay / spec["source"]
        target = None
    else:
        shutil.copytree(install_root(family, version), destination)
        for relative in spec["files"]:
            shutil.copy2(task / relative, destination / relative)
        source, target, overlay = destination / spec["source"], destination, None
    try:
        output = run_probe(family, version, target=target, overlay=overlay)
        assessments = verify_probe(output, family, version, source, cases, "fixed")
        return output, assessments, None
    except (AssertionError, subprocess.CalledProcessError, subprocess.TimeoutExpired,
            ValueError) as error:
        return None, None, str(error)[-1500:]


def run_attempt(index: int) -> None:
    freeze = load_freeze()
    key = freeze["schedule"][index]
    arm, family = key.split("-", 1)
    spec = FAMILIES[family]
    task = TASKS / key
    output = EVIDENCE / "runs" / (f"{index:02d}-" + key)
    output.mkdir(parents=True, exist_ok=False)
    prompt = (task / "prompt.txt").read_text(encoding="ascii")
    before = {relative: sha(task / relative) for relative in spec["files"]}
    known = {path.relative_to(task).as_posix(): sha(path) for path in task.rglob("*") if path.is_file()}
    host = run_host(host_command(task, output, freeze), prompt, output)
    after = {relative: sha(task / relative) for relative in spec["files"]}
    current = {path.relative_to(task).as_posix(): sha(path) for path in task.rglob("*") if path.is_file()}
    unexpected = (sorted(set(current) ^ set(known))
                  + sorted(path for path in set(known) & set(current)
                           if path not in spec["files"] and known[path] != current[path]))
    changed = [relative for relative in spec["files"] if before[relative] != after[relative]]
    cases = [case for case in json.loads(CASES.read_text(encoding="ascii"))["cases"]
             if case["family"] == family]
    oracle, assessments, error = (patched_oracle(family, key, task, cases) if changed and not unexpected
                                  else (None, None, None))
    status = assess_attempt(host["exit_code"], bool(changed), bool(unexpected), assessments)
    trace = []
    for line in (output / "host.jsonl").read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            trace.append(json.loads(line))
        except json.JSONDecodeError:
            trace.append({"type": "invalid_jsonl"})
    file_events = sum(item.get("type") == "item.completed"
                      and (item.get("item") or {}).get("type") == "file_change" for item in trace)
    result = {"key": key, "arm": arm, "family": family, "status": status,
              "host": host, "file_change_events": file_events, "changed_files": changed,
              "unexpected_files": unexpected, "before_sha256": before, "after_sha256": after,
              "oracle": oracle, "assessments": assessments, "oracle_error": error,
              "source_sha256_after": sha(task / spec["source"]),
              "frozen_inputs_unchanged": bool(load_freeze())}
    write_json(output / "run.json", result)
    print(json.dumps({"index": index, "key": key, "status": status,
                      "exit_code": host["exit_code"], "changed": len(changed),
                      "private_passed": sum(item["pass"] for item in assessments or [])}))


def report() -> None:
    freeze = load_freeze()
    rows = []
    for index, key in enumerate(freeze["schedule"]):
        path = EVIDENCE / "runs" / (f"{index:02d}-" + key) / "run.json"
        if path.is_file():
            rows.append(json.loads(path.read_text(encoding="ascii")))
        else:
            rows.append({"key": key, "arm": key[0], "family": key[2:], "status": "not_run"})
    arms = {arm: {status: sum(row["arm"] == arm and row["status"] == status for row in rows)
                  for status in ("success", "failed", "incomplete", "not_run")}
            for arm in ("A", "C")}
    summary = {"status": "COMPLETE" if all(row["status"] != "not_run" for row in rows) else "PARTIAL",
               "scope": "five_correlated_upstream_source_tasks_one_attempt_per_arm",
               "freeze_sha256": sha(FREEZE), "cases_sha256": freeze["cases_sha256"],
               "arms": arms, "rows": [{key: row.get(key) for key in ("key", "arm", "family", "status")}
                                      for row in rows],
               "limitations": ["Descriptive comparison only; no broad or causal benefit claim.",
                               "Boundary oracle only; no complete upstream test suite or exploit run.",
                               "Candidate guidance remains unreviewed and unpromoted."]}
    output = EVIDENCE / "summary.json"
    if output.exists():
        output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="ascii")
    else:
        write_json(output, summary)
    print(json.dumps({"status": summary["status"], "arms": arms, "output": str(output)}))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("prepare", "run", "report"))
    parser.add_argument("--index", type=int)
    args = parser.parse_args()
    if args.action == "prepare":
        prepare()
    elif args.action == "run":
        if args.index is None:
            raise ValueError("--index is required")
        run_attempt(args.index)
    else:
        report()


if __name__ == "__main__":
    main()
