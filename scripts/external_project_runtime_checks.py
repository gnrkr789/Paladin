"""Preserve supplementary upstream-suite and local Mercurial checks."""
import argparse
import json
import os

from scripts.external_project_comparison import CACHE, EVIDENCE, PYTHON, ROOT, invoke, save, sha


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", required=True)
    parser.add_argument("--retry", action="store_true")
    args = parser.parse_args()
    key = args.key
    project = key.split("-", 1)[0]
    target = CACHE / "tasks" / key
    directory = EVIDENCE / ("runtime-checks-retry" if args.retry else "runtime-checks") / key
    directory.mkdir(parents=True, exist_ok=False)
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(target)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    if project == "cookiecutter":
        temporary = CACHE / "test-temp" / (key + ("-retry" if args.retry else ""))
        temporary.parent.mkdir(parents=True, exist_ok=True)
        command = [PYTHON, "-B", "-m", "pytest", "-o", "addopts=", "-q", "tests/vcs",
                   "--basetemp=" + str(temporary)]
        cwd = target
    else:
        command = [PYTHON, "-B", "runtests.py", "db_functions", "--settings=test_sqlite", "--parallel", "1", "--noinput"]
        cwd = target / "tests"
    run = invoke(command, cwd=cwd, env=environment)
    (directory / "upstream.stdout.bin").write_bytes(run.stdout)
    (directory / "upstream.stderr.bin").write_bytes(run.stderr)
    record = {"key": key, "upstream_exit_code": run.returncode, "command": [str(x) for x in command],
              "cwd": str(cwd), "pythonpath": str(target)}
    if project == "cookiecutter":
        probe = ROOT / "eval/external_mercurial_probe.py"
        check = invoke([PYTHON, "-B", probe, "--target", target])
        (directory / "mercurial.stdout.bin").write_bytes(check.stdout)
        (directory / "mercurial.stderr.bin").write_bytes(check.stderr)
        record.update(mercurial_exit_code=check.returncode, mercurial_probe_sha256=sha(probe),
                      mercurial=json.loads(check.stdout) if check.returncode == 0 else None)
    save(directory / "result.json", record)
    print(json.dumps({"key": key, "upstream_exit": run.returncode,
                      "mercurial_passed": record.get("mercurial", {}).get("passed")}))


if __name__ == "__main__":
    main()
