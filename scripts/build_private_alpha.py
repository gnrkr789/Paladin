"""Build local private-alpha artifacts and verify a clean locked installation."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile


ROOT = Path(__file__).resolve().parents[1]
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))["project"]["version"]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inspect_artifacts(wheel, sdist, root=ROOT):
    """Check both distributions contain every authored Python and runtime resource."""
    source = root / "src" / "paladin"
    expected = {"paladin/" + p.relative_to(source).as_posix(): sha256(p)
                for p in source.rglob("*") if p.is_file()
                and (p.suffix == ".py" or "resources" in p.relative_to(source).parts)
                and "__pycache__" not in p.parts}
    if not any(name.startswith("paladin/resources/sandbox/") for name in expected):
        raise ValueError("Sandbox runtime resources are missing")
    report = {}
    with zipfile.ZipFile(wheel) as archive:
        actual = {name: hashlib.sha256(archive.read(name)).hexdigest()
                  for name in expected if name in archive.namelist()}
        if actual != expected:
            raise ValueError("Wheel source/resource contents differ from checkout")
        report["wheel_files"] = actual
    with tarfile.open(sdist) as archive:
        members = {m.name.split("/src/", 1)[1]: m for m in archive.getmembers()
                   if m.isfile() and "/src/" in m.name}
        actual = {name: hashlib.sha256(archive.extractfile(members[name]).read()).hexdigest()
                  for name in expected if name in members}
        if actual != expected:
            raise ValueError("Sdist source/resource contents differ from checkout")
        report["sdist_files"] = actual
    return report


SMOKE = r'''
import asyncio
import importlib.metadata
import importlib.resources
import json
from pathlib import Path
import sys
import paladin
from mcp import Client, StdioServerParameters
from paladin.advisory import INPUT_SCHEMAS

checkout, environment, workspace, version = map(str, sys.argv[1:])
checkout = Path(checkout).resolve()
environment = Path(environment).resolve()
workspace = Path(workspace).resolve()
assert importlib.metadata.version("paladin") == version
resource_root = importlib.resources.files("paladin").joinpath("resources")
resources = sorted(p.name for p in resource_root.joinpath("sandbox").iterdir() if p.is_file())
assert resources
assert resource_root.joinpath("prevention-pack.json").is_file()

async def discover():
    async with Client(StdioServerParameters(command=sys.executable,
            args=["-I", "-B", "-m", "paladin.cli", "mcp", "--workspace", str(workspace)]),
            read_timeout_seconds=35) as client:
        tools = (await client.list_tools()).tools
        names = sorted(tool.name for tool in tools)
        assert names == sorted(INPUT_SCHEMAS), names
        return {"protocol_version": client.protocol_version, "tools": names}

discovery = asyncio.run(discover())
modules = {}
for name, module in sorted(sys.modules.items()):
    if name == "paladin" or name.startswith("paladin."):
        path = Path(module.__file__).resolve()
        assert path.is_relative_to(environment), (name, path)
        assert not path.is_relative_to(checkout), (name, path)
        modules[name] = str(path)
print(json.dumps({"version": version, "module_paths": modules,
                  "sandbox_resources": resources, "mcp_discovery": discovery}, indent=2))
'''


RUNTIME_SUBJECTS = [
    ("cookiecutter-2.1.0", ROOT / ".validation-cache" / "upstream" / "cookiecutter-2.1.0", "CVE-2022-24065"),
    ("pip-23.2.1", ROOT / ".validation-cache" / "private-alpha-projects" / "pip-23.2.1", "CVE-2023-5752"),
]


def tree_sha256(root):
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8") + b"\0" + sha256(path).encode("ascii"))
    return digest.hexdigest()


def installed_runtime(run, cli, validation, evidence):
    """Exercise runtime policy, real isolated verification, promotion, listing and reuse."""
    workspace = validation / "runtime-workspace"
    workspace.mkdir()
    subject, project, _ = RUNTIME_SUBJECTS[0]
    refused = subprocess.run([str(cli), "cases", "auto", "--project", str(project),
                              "--workspace", str(workspace), "--json"],
                             capture_output=True, text=True, encoding="utf-8", timeout=600)
    (evidence / "runtime-unconfigured.stdout.txt").write_text(refused.stdout, encoding="utf-8")
    unconfigured = json.loads(refused.stdout)
    reasons = [item.get("reason") for item in unconfigured.get("case_runs", [])]
    assert refused.returncode == 1 and reasons == ["runtime_not_configured"], unconfigured
    built = json.loads(run("runtime-build", [cli, "cases", "runtime-build", "--workspace", workspace,
                                             "--json"], cwd=workspace, timeout=1200))
    assert built["status"] == "ready", built
    results = {"unconfigured_reasons": reasons, "runtime": built["runtime"], "subjects": []}
    for subject, project, cve in RUNTIME_SUBJECTS:
        before = tree_sha256(project)
        # Whole-project scans report unsupported shapes, so `partial` exits 1 by design.
        auto = json.loads(run(subject + "-auto", [cli, "cases", "auto", "--project", project,
                                                  "--workspace", workspace, "--json"],
                              cwd=workspace, timeout=1800, allowed=(0, 1)))
        runs = auto["case_runs"]
        assert len(runs) == 1 and runs[0]["status"] == "promoted", runs
        listed = json.loads(run(subject + "-list", [cli, "cases", "list", "--workspace", workspace,
                                                    "--cve", cve, "--json"], cwd=workspace))
        assert listed["status"] == "complete" and len(listed["cases"]) == 1, listed
        reuse = json.loads(run(subject + "-reuse", [cli, "cases", "auto", "--project", project,
                                                    "--workspace", workspace, "--json"],
                               cwd=workspace, timeout=600, allowed=(0, 1)))
        assert [item.get("reused") for item in reuse["case_runs"]] == [True], reuse
        assert tree_sha256(project) == before, subject
        results["subjects"].append({"subject": subject, "checks": runs[0]["checks"],
                                    "case_id": runs[0]["case"]["case_id"],
                                    "evidence_sha256": runs[0]["evidence_sha256"],
                                    "listed_case_ids": [item["case_id"] for item in listed["cases"]],
                                    "reused": True, "source_tree_sha256": before,
                                    "source_unchanged": True})
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, default=ROOT / "dist" / "private-alpha")
    parser.add_argument("--evidence", type=Path, default=ROOT / "docs" / "evidence" / "private-alpha" / "package")
    parser.add_argument("--skip-build", action="store_true", help="verify existing artifacts")
    parser.add_argument("--skip-runtime", action="store_true",
                        help="skip the installed Docker runtime, verification and reuse checks")
    args = parser.parse_args(argv)
    artifacts, evidence = args.artifacts.resolve(), args.evidence.resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "report.json").write_text(
        json.dumps({"status": "IN_PROGRESS", "version": VERSION}) + "\n", encoding="ascii")
    env = {key: value for key, value in os.environ.items()
           if key.upper() not in {"PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"}}
    env["UV_CACHE_DIR"] = str(ROOT / ".cache" / "uv")
    commands = []

    def run(label, command, cwd=ROOT, timeout=600, allowed=(0,)):
        process = subprocess.run([str(part) for part in command], cwd=cwd, env=env,
                                 capture_output=True, text=True, encoding="utf-8",
                                 errors="replace", timeout=timeout)
        (evidence / (label + ".stdout.txt")).write_text(process.stdout, encoding="utf-8")
        (evidence / (label + ".stderr.txt")).write_text(process.stderr, encoding="utf-8")
        commands.append({"label": label, "command": [str(p) for p in command],
                         "cwd": str(cwd), "exit_code": process.returncode})
        (evidence / "commands.json").write_text(json.dumps(commands, indent=2) + "\n", encoding="ascii")
        if process.returncode not in allowed:
            raise RuntimeError(f"{label} failed; inspect {evidence}")
        return process.stdout

    if not args.skip_build:
        run("build", ["uv", "build", "--out-dir", artifacts])
    wheel = artifacts / f"paladin-{VERSION}-py3-none-any.whl"
    sdist = artifacts / f"paladin-{VERSION}.tar.gz"
    report = {"version": VERSION, "artifacts": {
        path.name: {"sha256": sha256(path), "bytes": path.stat().st_size}
        for path in (wheel, sdist)}}
    report.update(inspect_artifacts(wheel, sdist))
    requirements = run("export", ["uv", "export", "--frozen", "--no-dev", "--no-emit-project",
                                  "--format", "requirements-txt"])
    (evidence / "requirements.lock.txt").write_text(requirements, encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="paladin-private-alpha-") as temporary:
        validation = Path(temporary) / ".validation-cache" / "private-alpha-install"
        validation.mkdir(parents=True)
        venv, workspace = validation / "venv", validation / "workspace"
        workspace.mkdir()
        run("venv", ["uv", "venv", "--python", "3.12", venv], cwd=workspace)
        python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        cli = venv / ("Scripts/paladin.exe" if os.name == "nt" else "bin/paladin")
        run("dependencies", ["uv", "pip", "install", "--python", python, "--require-hashes",
                             "-r", evidence / "requirements.lock.txt"], cwd=workspace)
        run("install", ["uv", "pip", "install", "--python", python, "--no-deps", wheel], cwd=workspace)
        run("dependency-check", ["uv", "pip", "check", "--python", python], cwd=workspace)
        run("help", [cli, "--help"], cwd=workspace)
        project = validation / "sample-project"
        project.mkdir()
        (project / "checkout.py").write_text(
            "import subprocess\ndef checkout(value):\n    subprocess.run(['hg', 'checkout', value])\n", encoding="ascii")
        scan = json.loads(run("cases-scan", [cli, "cases", "scan", "--project", project,
                                            "--workspace", workspace, "--json"], cwd=workspace))
        assert scan["status"] == "complete" and len(scan["candidates"]) == 1, scan
        script = validation / "installed_smoke.py"
        script.write_text(SMOKE, encoding="ascii")
        smoke = json.loads(run("installed-smoke", [python, "-I", "-B", script, ROOT,
                                                  venv, workspace, VERSION], cwd=workspace))
        report.update(smoke)
        if not args.skip_runtime:
            report["installed_runtime"] = installed_runtime(run, cli, validation, evidence)
        report["clean_install_root"] = str(validation)
        report["clean_install_removed_after_verification"] = True
        report["case_scan"] = scan
    report["status"] = "PASS"
    (evidence / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="ascii")
    print(json.dumps({"status": "PASS", "version": VERSION, "evidence": str(evidence)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
