"""Run one bounded real Codex task; no persistent host configuration changes."""
import hashlib
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
import tomllib

from smoke_m3 import state_snapshot


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--retry", action="store_true", help="approved single retry with automatic approval review")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = root / "docs/evidence/m4" / "retry-001" if args.retry else root / "docs/evidence/m4"
    task = root / ".cache/m4-task" / ("run-002" if args.retry else "run-001")
    if args.retry:
        assert not output.exists() and not task.exists(), "Only one fresh approved retry is permitted"
        output.mkdir(parents=True)
        task.mkdir(parents=True)
        shutil.copyfile(root / "eval/m4/containment.before.py", task / "containment.py")
    else:
        output.mkdir(parents=True, exist_ok=True)
    before = root / "eval/m4/containment.before.py"
    target = task / "containment.py"
    assert target.read_bytes() == before.read_bytes(), "Do not overwrite a prior task result"
    executable = (Path("C:/Users/user/AppData/Roaming/npm/node_modules/@openai/codex/node_modules")
                  / "@openai/codex-win32-x64/vendor/x86_64-pc-windows-msvc/bin/codex.exe")
    assert executable.is_file()
    config = Path("C:/Users/user/.codex/config.toml")
    config_before = hashlib.sha256(config.read_bytes()).hexdigest()
    settings = tomllib.loads(config.read_text(encoding="utf-8"))
    selected = {k: settings[k] for k in ["model", "model_reasoning_effort"] if k in settings}
    prompt = f"""This is a bounded Paladin M4 host integration task in an isolated synthetic example.
Use English only. You own only {target}. Do not modify tests or any other file.
Inspect containment.py and correct lexical Windows path containment while retaining ordinary children,
nested children, root equality and case normalization. Reject sibling-prefix paths, parent traversal
into a sibling and different-drive paths. This is lexical analysis, not symlink/race protection.
Before editing, call Paladin get_knowledge_status, search_prevention_patterns with an English intent
describing this issue, and get_pattern_evidence using the returned pattern ID, pack hash and evidence IDs.
Use metadata-only evidence. Read the actual returned prerequisites and limitations before choosing a fix.
Do not read Paladin's pack/source files directly as a substitute for MCP tool calls.
After editing run this independent behavior test without changing it:
{root / '.venv/Scripts/python.exe'} -B {root / 'eval/m4/test_containment.py'} {target}
Then call Paladin check_changes with an empty object and report its actual capability.
In your final answer identify the retrieved CVE, actual source conditions you used, your correction,
test outcome and limits. Do not claim Paladin inspected the code, approved a rule, enforced a gate,
reproduced a CVE or proved vulnerability prevention. Stop after this task.
"""
    (output / "prompt.txt").write_text(prompt, encoding="utf-8")
    task.joinpath("AGENTS.md").write_text(
        "# M4 isolated task\n\nUse English. Edit only containment.py. Do not change independent tests.\n"
        "Use the configured Paladin MCP for advisory knowledge before editing.\n"
        "Stop after the requested correction and report the unsupported inspection boundary.\n", encoding="utf-8")
    command = [str(executable), "exec", "--ignore-user-config", "--ephemeral", "--skip-git-repo-check",
               *( ["--approve-for-me"] if args.retry else ["--sandbox", "workspace-write"] ),
               "--json", "--color", "never", "--cd", str(task),
               "--output-last-message", str(output / "final.txt")]
    overrides = {**selected,
                 "mcp_servers.paladin.command": str(root / ".venv/Scripts/python.exe"),
                 "mcp_servers.paladin.args": ["-B", "-m", "paladin.cli", "mcp", "--workspace", str(root)],
                 "mcp_servers.paladin.cwd": str(root),
                 "mcp_servers.paladin.startup_timeout_sec": 20,
                 "mcp_servers.paladin.tool_timeout_sec": 40,
                 "mcp_servers.paladin.enabled_tools": ["get_knowledge_status", "search_prevention_patterns",
                                                       "get_pattern_evidence", "check_changes"]}
    for key, value in overrides.items():
        command += ["-c", key + "=" + json.dumps(value)]
    command += ["-"]
    snapshot = state_snapshot(root)
    test_before = hashlib.sha256((root / "eval/m4/test_containment.py").read_bytes()).hexdigest()
    (output / "before-state.json").write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    version = subprocess.run([str(executable), "--version"], capture_output=True, text=True, check=True).stdout.strip()
    report = {"host_version": version, "settings": selected, "timeout_seconds": 300,
              "configuration_scope": "invocation only; ignore unrelated user config; preserve selected model/effort",
              "command": command, "status": "started", "approved_retry": args.retry,
              "permission_request": "workspace-write/on-request/auto_review" if args.retry else "workspace-write"}
    started = time.monotonic()
    import win32api
    import win32job
    job = win32job.CreateJobObject(None, "")
    limits = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
    limits["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, limits)
    process = None
    try:
        with (output / "host.jsonl").open("wb") as stdout, (output / "host.stderr.txt").open("wb") as stderr:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
            win32job.AssignProcessToJobObject(job, int(process._handle))
            try:
                process.communicate(prompt.encode(), timeout=300)
                report["exit_code"] = process.returncode
                report["status"] = "host_finished" if process.returncode == 0 else "host_failed"
            except subprocess.TimeoutExpired:
                win32job.TerminateJobObject(job, 1)
                process.wait(timeout=5)
                report["status"] = "timeout"
    finally:
        win32job.TerminateJobObject(job, 1)
        win32api.CloseHandle(job)
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        report["elapsed_seconds"] = time.monotonic() - started
        report["global_config_unchanged"] = hashlib.sha256(config.read_bytes()).hexdigest() == config_before
        report["authoritative_files_unchanged"] = state_snapshot(root) == snapshot
        report["independent_test_sha256"] = hashlib.sha256((root / "eval/m4/test_containment.py").read_bytes()).hexdigest()
        report["independent_test_unchanged"] = report["independent_test_sha256"] == test_before
        shutil.copyfile(target, output / "containment.after.py")
        (output / "run.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "command"}))
    return 0 if report["status"] == "host_finished" else 1


if __name__ == "__main__":
    raise SystemExit(main())
