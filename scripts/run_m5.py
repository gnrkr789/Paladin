"""Freeze and run the bounded M5 advisory comparison."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import time
import tomllib

from eval.m5_catalog import build_cases
from eval.m5_harness import freeze_protocol, load_protocol, score_attempt, summarize
from scripts.smoke_m3 import state_snapshot


ROOT = Path(__file__).resolve().parents[1]
EVAL = ROOT / "eval/m5"
PROTOCOL = EVAL / "protocol.json"
EVIDENCE = ROOT / "docs/evidence/m5"
TASKS = ROOT / ".cache/m5-tasks"
CODEX = (Path("C:/Users/user/AppData/Roaming/npm/node_modules/@openai/codex/node_modules")
         / "@openai/codex-win32-x64/vendor/x86_64-pc-windows-msvc/bin/codex.exe")
CONFIG = Path("C:/Users/user/.codex/config.toml")
MAX_RUNS = 120
TIMEOUT_SECONDS = 180


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _selected_settings() -> tuple[str, str]:
    settings = tomllib.loads(CONFIG.read_text(encoding="utf-8"))
    return settings["model"], settings["model_reasoning_effort"]


def _host_version() -> str:
    return subprocess.run([str(CODEX), "--version"], capture_output=True,
                          text=True, check=True, timeout=15).stdout.strip()


def command_for_arm(arm: str, *, executable: str, task: str, output: str,
                    model: str, effort: str, project: str,
                    approve_for_me: bool = False) -> list[str]:
    if arm not in ("A", "B", "C"):
        raise ValueError("Only advisory arms A, B and C are eligible")
    command = [executable, "exec", "--ignore-user-config", "--ephemeral",
               "--skip-git-repo-check"]
    command += ["--approve-for-me"] if approve_for_me else ["--sandbox", "workspace-write"]
    command += ["--json", "--color", "never", "--cd", task,
                "--output-last-message", output]
    overrides = {"model": model, "model_reasoning_effort": effort}
    if arm == "C":
        overrides.update({
            "mcp_servers.paladin.command": str(Path(project) / ".venv/Scripts/python.exe"),
            "mcp_servers.paladin.args": ["-B", "-m", "paladin.cli", "mcp",
                                          "--workspace", project],
            "mcp_servers.paladin.cwd": project,
            "mcp_servers.paladin.startup_timeout_sec": 20,
            "mcp_servers.paladin.tool_timeout_sec": 40,
            "mcp_servers.paladin.enabled_tools": [
                "get_knowledge_status", "search_prevention_patterns", "get_pattern_evidence"
            ],
        })
    for key, value in overrides.items():
        command += ["-c", key + "=" + json.dumps(value)]
    return command + ["-"]


def inspect_trace(events: list[dict]) -> dict:
    """Require successful evidence and visible use before the first file edit."""
    called = False
    completed_evidence: list[tuple[int, str]] = []
    messages: list[tuple[int, str]] = []
    first_edit = None
    usage = {}
    for index, event in enumerate(events):
        if event.get("type") == "turn.completed":
            usage = event.get("usage") or usage
        if event.get("type") != "item.completed":
            continue
        item = event.get("item") or {}
        if item.get("type") == "file_change" and first_edit is None:
            first_edit = index
        elif item.get("type") == "agent_message":
            messages.append((index, item.get("text") or ""))
        elif item.get("type") == "mcp_tool_call" and item.get("server") == "paladin":
            result = (item.get("result") or {}).get("structured_content") or {}
            if item.get("status") == "completed" and result.get("status") in ("ready", "complete"):
                called = True
                if item.get("tool") == "get_pattern_evidence" and result.get("pattern_id"):
                    completed_evidence.append((index, result["pattern_id"]))
    consumed = any(
        evidence_index < message_index < (first_edit if first_edit is not None else len(events))
        and pattern_id in message
        for evidence_index, pattern_id in completed_evidence
        for message_index, message in messages
    )
    return {"called": called, "consumed": consumed,
            "pattern_ids": sorted({pattern for _, pattern in completed_evidence}),
            "file_change_event": first_edit is not None,
            "usage": usage}


def _events(path: Path) -> list[dict]:
    events = []
    if not path.is_file():
        return events
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            events.append({"type": "invalid_jsonl"})
    return events


def _prompt(arm: str, case_prompt: str) -> str:
    if arm == "A":
        addition = ""
    elif arm == "B":
        addition = (
            "Apply general secure coding practices. Validate untrusted input, "
            "avoid injection, and preserve useful behavior.\n"
        )
    elif arm == "C":
        addition = (
            "Before editing, call Paladin get_knowledge_status, "
            "search_prevention_patterns with an English intent for this task, "
            "and get_pattern_evidence for a relevant result using returned IDs "
            "and the pack hash. Use the returned conditions and limits as "
            "advisory evidence. State which evidence informed your change "
            "before editing. Do not claim Paladin inspected or approved code.\n"
        )
    else:
        raise ValueError("Unknown arm")
    return case_prompt + addition


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="ascii", newline="\n") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=True)
        stream.write("\n")


def prepare() -> dict:
    if PROTOCOL.exists() or (EVIDENCE / "freeze.json").exists():
        raise FileExistsError("M5 protocol or freeze evidence already exists; preserve it")
    pilots = [EVIDENCE / name / "assessment.json"
              for name in ("pilot", "pilot-elevated", "pilot-approved")]
    completed_pilots = [json.loads(path.read_text(encoding="ascii"))
                        for path in pilots if path.is_file()]
    successful_pilots = [item for item in completed_pilots
                         if item.get("host_edit") and item.get("independent_test_pass")
                         and item.get("global_config_unchanged")
                         and item.get("authoritative_files_unchanged")]
    if not successful_pilots:
        raise RuntimeError("Unscored host pilot did not meet the edit/test gate")
    pilot_result = successful_pilots[-1]
    if not CODEX.is_file() or not CONFIG.is_file():
        raise FileNotFoundError("Codex CLI or selected configuration unavailable")
    model, effort = _selected_settings()
    cases = build_cases(EVAL)
    if len(cases) != 40:
        raise ValueError("Expected 40 task cases")
    baseline = {}
    for case in cases:
        result = subprocess.run([str(ROOT / ".venv/Scripts/python.exe"), "-I", "-B",
                                 str(case["oracle"]), case["id"], str(case["source"])],
                                capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise RuntimeError(f"Baseline oracle failed for {case['id']}: {result.stdout} {result.stderr}")
        finding = json.loads(result.stdout)
        if finding["functional"] or finding["vulnerable"] != (case["kind"] == "weakness"):
            raise RuntimeError(f"Unexpected baseline for {case['id']}: {finding}")
        baseline[case["id"]] = finding
    host = {"codex_version": _host_version(), "model": model, "effort": effort,
            "permission_mode": pilot_result["permission_mode"],
            "timeout_seconds": TIMEOUT_SECONDS,
            "max_scored_runs": MAX_RUNS, "python": sys.version.split()[0],
            "codex_sha256": _sha(CODEX), "config_sha256": _sha(CONFIG),
            "runner_sha256": _sha(Path(__file__)),
            "harness_sha256": _sha(ROOT / "eval/m5_harness.py"),
            "catalog_sha256": _sha(ROOT / "eval/m5_catalog.py"),
            "oracle_source_sha256": _sha(ROOT / "eval/m5_oracle.py"),
            "authoritative_state": state_snapshot(ROOT)}
    protocol = freeze_protocol(PROTOCOL, cases, arms=("A", "B", "C"),
                               repeats=1, seed=517)
    if len(protocol["schedule"]) != MAX_RUNS:
        raise ValueError("Unexpected schedule size")
    _write_json(EVIDENCE / "freeze.json", {
        "protocol_sha256": _sha(PROTOCOL), "host": host,
        "baseline": baseline, "task_count": len(cases),
        "weakness_tasks": 20, "safe_tasks": 20,
        "distinct_code_structures": 4,
        "limitation": "Five context variants per family share one code structure.",
    })
    return {"protocol_sha256": _sha(PROTOCOL), "tasks": len(cases),
            "scheduled_runs": len(protocol["schedule"]), "host": host}


def _run_host(command: list[str], prompt: str, output: Path) -> dict:
    """Capture a real Codex run and reap all children on Windows."""
    import win32api
    import win32job

    job = win32job.CreateJobObject(None, "")
    limits = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
    limits["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, limits)
    process = None
    result = {"status": "started", "exit_code": None}
    started = time.monotonic()
    try:
        with (output / "host.jsonl").open("xb") as stdout, (
                output / "host.stderr.txt").open("xb") as stderr:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=stdout,
                                       stderr=stderr, creationflags=subprocess.CREATE_NO_WINDOW)
            win32job.AssignProcessToJobObject(job, int(process._handle))
            try:
                process.communicate(prompt.encode("ascii"), timeout=TIMEOUT_SECONDS)
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


def pilot(*, approve_for_me: bool = False, tag: str = "pilot") -> dict:
    """One unscored host edit with an independent behavior check."""
    if tag not in ("pilot", "pilot-elevated", "pilot-approved"):
        raise ValueError("Invalid pilot tag")
    output = EVIDENCE / tag
    task = TASKS / tag
    if output.exists() or task.exists():
        raise FileExistsError("Pilot evidence or task exists; preserve it")
    output.mkdir(parents=True)
    task.mkdir(parents=True)
    source = task / "source.py"
    source.write_text(
        '"""Unscored host edit pilot."""\n\n'
        'def tag(value):\n'
        '    return "old:" + value\n', encoding="ascii")
    (task / "AGENTS.md").write_text(
        "# Isolated M5 pilot\n\nUse English. Edit only source.py.\n", encoding="ascii")
    prompt = (
        "Edit only source.py. Change tag(value) to return 'new:' followed by value. "
        "Run a local check that tag('x') returns 'new:x'. Stop after reporting the result.\n"
    )
    (output / "prompt.txt").write_text(prompt, encoding="ascii")
    model, effort = _selected_settings()
    before = _sha(source)
    snapshot = state_snapshot(ROOT)
    config_sha = _sha(CONFIG)
    command = command_for_arm("A", executable=str(CODEX), task=str(task),
                              output=str(output / "final.txt"), model=model, effort=effort,
                              project=str(ROOT), approve_for_me=approve_for_me)
    result = _run_host(command, prompt, output)
    after = _sha(source)
    trace = inspect_trace(_events(output / "host.jsonl"))
    try:
        spec = __import__("importlib.util", fromlist=["spec_from_file_location"])
        module_spec = spec.spec_from_file_location("m5_pilot_target", source)
        module = spec.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        passed = module.tag("x") == "new:x" and module.tag("") == "new:"
    except Exception:
        passed = False
    result.update({"host_edit": before != after and trace["file_change_event"],
                   "independent_test_pass": passed,
                   "global_config_unchanged": _sha(CONFIG) == config_sha,
                   "authoritative_files_unchanged": state_snapshot(ROOT) == snapshot,
                   "permission_mode": "approve-for-me" if approve_for_me else "workspace-write"})
    shutil.copyfile(source, output / "source.after.py")
    _write_json(output / "assessment.json", result)
    return result


def _verify_host_freeze(freeze: dict) -> None:
    host = freeze["host"]
    model, effort = _selected_settings()
    if (host["codex_version"] != _host_version()
            or host["model"] != model or host["effort"] != effort
            or host["codex_sha256"] != _sha(CODEX)
            or host["config_sha256"] != _sha(CONFIG)
            or host["runner_sha256"] != _sha(Path(__file__))
            or host["harness_sha256"] != _sha(ROOT / "eval/m5_harness.py")
            or host["catalog_sha256"] != _sha(ROOT / "eval/m5_catalog.py")
            or host["oracle_source_sha256"] != _sha(ROOT / "eval/m5_oracle.py")
            or host["authoritative_state"] != state_snapshot(ROOT)):
        raise RuntimeError("Frozen host/model/authoritative state changed")
    if freeze["protocol_sha256"] != _sha(PROTOCOL):
        raise RuntimeError("Frozen protocol changed")


def run_attempt(index: int, item: dict, protocol: dict, freeze: dict) -> dict:
    case = next(case for case in protocol["cases"] if case["id"] == item["case_id"])
    arm = item["arm"]
    name = f"{index:03d}-{case['id']}-{arm}"
    output = EVIDENCE / "runs" / name
    task = TASKS / name
    if output.exists() or task.exists():
        raise FileExistsError(f"Run exists; preserve it: {name}")
    output.mkdir(parents=True)
    task.mkdir(parents=True)
    source = task / "source.py"
    source_original = EVAL / case["files"]["source"]["path"]
    shutil.copyfile(source_original, source)
    (task / "AGENTS.md").write_text(
        "# Isolated M5 task\n\nUse English. Edit only source.py. "
        "Do not modify independent tests.\n", encoding="ascii")
    case_prompt = (EVAL / case["files"]["prompt"]["path"]).read_text(encoding="ascii")
    prompt = _prompt(arm, case_prompt)
    (output / "prompt.txt").write_text(prompt, encoding="ascii")
    before = _sha(source)
    model, effort = freeze["host"]["model"], freeze["host"]["effort"]
    command = command_for_arm(arm, executable=str(CODEX), task=str(task),
                              output=str(output / "final.txt"), model=model, effort=effort,
                              project=str(ROOT),
                              approve_for_me=freeze["host"]["permission_mode"] == "approve-for-me")
    started = time.monotonic()
    host = _run_host(command, prompt, output)
    after = _sha(source)
    trace = inspect_trace(_events(output / "host.jsonl"))
    oracle_path = EVAL / case["files"]["oracle"]["path"]
    oracle = subprocess.run([str(ROOT / ".venv/Scripts/python.exe"), "-I", "-B",
                             str(oracle_path), case["id"], str(source)],
                            capture_output=True, text=True, timeout=15)
    finding = None
    if oracle.returncode == 0:
        finding = json.loads(oracle.stdout)
    score = score_attempt(
        kind=case["kind"], arm=arm, host_exit=host["exit_code"],
        before_sha=before, after_sha=after,
        functionality=finding["functional"] if finding else None,
        vulnerability=finding["vulnerable"] if finding else None,
        called=trace["called"], consumed=trace["consumed"],
    )
    result = {"index": index, "case_id": case["id"], "kind": case["kind"],
              "family": case["family"], "arm": arm, "repeat": item["repeat"],
              "before_sha256": before, "after_sha256": after,
              "host": host, "trace": trace, "oracle": finding,
              "oracle_exit": oracle.returncode, "score": score,
              "elapsed_total_seconds": time.monotonic() - started,
              "host_jsonl_bytes": (output / "host.jsonl").stat().st_size,
              "authoritative_files_unchanged": state_snapshot(ROOT) == freeze["host"]["authoritative_state"],
              "global_config_unchanged": _sha(CONFIG) == freeze["host"]["config_sha256"]}
    shutil.copyfile(source, output / "source.after.py")
    (output / "oracle.stdout.txt").write_text(oracle.stdout, encoding="utf-8")
    (output / "oracle.stderr.txt").write_text(oracle.stderr, encoding="utf-8")
    _write_json(output / "run.json", result)
    return result


def run_all() -> dict:
    protocol = load_protocol(PROTOCOL)
    freeze = json.loads((EVIDENCE / "freeze.json").read_text(encoding="ascii"))
    _verify_host_freeze(freeze)
    if len(protocol["schedule"]) != MAX_RUNS:
        raise RuntimeError("Frozen schedule must have exactly 120 attempts")
    completed = 0
    for index, item in enumerate(protocol["schedule"]):
        name = f"{index:03d}-{item['case_id']}-{item['arm']}"
        prior = EVIDENCE / "runs" / name / "run.json"
        if prior.exists():
            completed += 1
            continue
        _verify_host_freeze(freeze)
        result = run_attempt(index, item, protocol, freeze)
        completed += 1
        print(json.dumps({"index": index, "case": item["case_id"], "arm": item["arm"],
                          "status": result["score"]["status"],
                          "functional": result["score"]["functional"],
                          "vulnerable": result["score"]["vulnerable"],
                          "elapsed": round(result["elapsed_total_seconds"], 2)}), flush=True)
        if not result["authoritative_files_unchanged"] or not result["global_config_unchanged"]:
            raise RuntimeError("Host changed authoritative state or global configuration")
    return {"completed_runs": completed, "scheduled_runs": MAX_RUNS}


def report() -> dict:
    protocol = load_protocol(PROTOCOL)
    rows = []
    missing = []
    runs = []
    for index, item in enumerate(protocol["schedule"]):
        name = f"{index:03d}-{item['case_id']}-{item['arm']}"
        path = EVIDENCE / "runs" / name / "run.json"
        if not path.is_file():
            missing.append(name)
            continue
        run = json.loads(path.read_text(encoding="ascii"))
        runs.append(run)
        rows.append({"case_id": run["case_id"], "family": run["family"],
                     "arm": run["arm"], "kind": run["kind"], **run["score"]})
    summary = summarize(rows)
    families = {}
    for family in sorted({row["family"] for row in rows}):
        families[family] = summarize([row for row in rows if row["family"] == family])["arms"]
    summary["families"] = families
    summary["paladin_calls"] = {
        "C_recorded": sum(run["arm"] == "C" for run in runs),
        "C_called": sum(run["arm"] == "C" and run["trace"]["called"] for run in runs),
        "C_consumed": sum(run["arm"] == "C" and run["trace"]["consumed"] for run in runs),
    }
    summary["host_overhead"] = {}
    for arm in ("A", "B", "C"):
        arm_runs = [run for run in runs if run["arm"] == arm]
        durations = sorted(run["elapsed_total_seconds"] for run in arm_runs)
        if not durations:
            continue
        summary["host_overhead"][arm] = {
            "runs": len(arm_runs),
            "elapsed_p50_seconds": statistics.median(durations),
            "elapsed_p95_seconds": durations[max(0, (len(durations) * 95 + 99) // 100 - 1)],
            "host_jsonl_bytes": sum(run["host_jsonl_bytes"] for run in arm_runs),
            "input_tokens": sum(run["trace"]["usage"].get("input_tokens", 0) for run in arm_runs),
            "output_tokens": sum(run["trace"]["usage"].get("output_tokens", 0) for run in arm_runs),
            "peak_memory_bytes": None,
        }
    summary.update({"scheduled": len(protocol["schedule"]), "recorded": len(rows),
                    "missing": missing, "protocol_sha256": _sha(PROTOCOL),
                    "behavior_families": 4, "context_variants_per_family": 5,
                    "independence_limitation": "Context variants share one behavior family and similar source structure.",
                    "evaluation_complete": not missing,
                    "general_effectiveness_claim": False})
    path = EVIDENCE / ("summary.json" if not missing else f"summary.partial-{len(rows)}.json")
    if path.exists():
        raise FileExistsError("Summary exists; preserve prior report")
    _write_json(path, summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("pilot", "prepare", "run", "report"))
    parser.add_argument("--approve-for-me", action="store_true")
    parser.add_argument("--pilot-tag", choices=("pilot", "pilot-elevated", "pilot-approved"),
                        default="pilot")
    args = parser.parse_args()
    if args.approve_for_me and args.action != "pilot":
        parser.error("--approve-for-me is only valid for a pilot")
    if args.action == "pilot":
        result = pilot(approve_for_me=args.approve_for_me, tag=args.pilot_tag)
    elif args.action == "prepare":
        result = prepare()
    elif args.action == "run":
        result = run_all()
    else:
        result = report()
    print(json.dumps(result, ensure_ascii=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
