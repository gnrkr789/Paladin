"""Run authoritative fixed-release Cookiecutter regressions against agent repairs."""
import os
import shutil
from scripts.external_project_comparison import CACHE, EVIDENCE, PYTHON, invoke, save, sha


def main():
    source = CACHE / "upstream/cookiecutter"
    fixture = CACHE / "fixed-cookiecutter-tests"
    if fixture.exists():
        raise FileExistsError(fixture)
    shutil.copytree(source / "tests", fixture / "tests", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    blob = invoke(["git", "show", "2.1.1:tests/vcs/test_clone.py"], cwd=source)
    if blob.returncode:
        raise ValueError("fixed upstream test unavailable")
    test_file = fixture / "tests/vcs/test_clone.py"
    test_file.write_bytes(blob.stdout)
    commit = invoke(["git", "rev-parse", "2.1.1^{commit}"], cwd=source).stdout.decode().strip()
    result = {"kind": "posthoc_authoritative_fixed_release_tests", "fixed_commit": commit,
              "fixed_test_sha256": sha(test_file), "base_tests": "2.1.0 tests with 2.1.1 test_clone.py", "arms": {}}
    for arm in ("A", "B", "C", "D"):
        task = CACHE / "tasks" / ("cookiecutter-" + arm)
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(task)
        command = [PYTHON, "-B", "-m", "pytest", "-q", "-o", "addopts=", "tests/vcs",
                   "--basetemp=" + str(CACHE / "test-temp" / ("fixed-" + arm))]
        run = invoke(command, cwd=fixture, env=environment)
        output = EVIDENCE / "fixed-upstream-tests" / arm
        output.mkdir(parents=True, exist_ok=False)
        (output / "stdout.bin").write_bytes(run.stdout)
        (output / "stderr.bin").write_bytes(run.stderr)
        result["arms"][arm] = {"exit_code": run.returncode, "command": [str(x) for x in command]}
    save(EVIDENCE / "fixed-upstream-tests/result.json", result)
    print({arm: row["exit_code"] for arm, row in result["arms"].items()})


if __name__ == "__main__":
    main()
