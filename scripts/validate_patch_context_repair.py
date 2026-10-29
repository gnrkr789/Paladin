"""Validate a complete source-pinned BentoML reference repair in a fresh copy."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from paladin import advisory
from paladin.knowledge import _resource


def main():
    root = Path(__file__).resolve().parents[1]
    destination = root / ".validation-cache/patch-context-repair/bentoml-1.2.4"
    evidence = root / "docs/evidence/patch-context-repair"
    if destination.exists() or evidence.exists():
        raise FileExistsError("reference repair already exists")
    args = {"pattern_id": "CVE-2024-2912",
            "pack_sha256": hashlib.sha256(_resource("prevention-pack.json")).hexdigest(),
            "guidance_sha256": hashlib.sha256(_resource("guidance-pack.json")).hexdigest(),
            "include_patch_context": True}
    result = advisory.dispatch(root, "get_prevention_guidance", args)
    if result["status"] != "complete":
        raise ValueError("complete source context required")
    context = result["patch_context"]
    shutil.copytree(root / ".validation-cache/upstream/bentoml-1.2.4", destination,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    evidence.mkdir(parents=True)
    patch = evidence / "reference.patch"
    patch.write_bytes(context["patch"].encode("utf-8"))
    if hashlib.sha256(patch.read_bytes()).hexdigest() != context["sha256"]:
        raise ValueError("patch identity changed")
    for check in (True, False):
        command = ["git", "apply", "-p2"] + (["--check"] if check else []) + [str(patch)]
        applied = subprocess.run(command, cwd=destination, capture_output=True, check=False)
        (evidence / ("check.stderr" if check else "apply.stderr")).write_bytes(applied.stderr)
        if applied.returncode:
            raise RuntimeError("reference patch did not apply")
    python = "C:/Users/user/AppData/Roaming/uv/python/cpython-3.11-windows-x86_64-none/python.exe"
    command = [python, "-B", str(root / "eval/guidance_holdout_probe.py"),
               "--cases", str(root / "eval/guidance_agent_cases.json"),
               "--family", "unsafe_deserialization", "--target", str(destination),
               "--compat", str(root / ".validation-cache/upstream/legacy-bento-deps")]
    run = subprocess.run(command, cwd=root, capture_output=True, check=False, timeout=90)
    (evidence / "stdout.bin").write_bytes(run.stdout)
    (evidence / "stderr.bin").write_bytes(run.stderr)
    if run.returncode:
        raise RuntimeError("reference probe failed")
    output = json.loads(run.stdout)
    cases = json.loads((root / "eval/guidance_agent_cases.json").read_text(encoding="ascii"))["cases"]
    cases = [case for case in cases if case["family"] == "unsafe_deserialization"]
    checks = [{"id": case["id"], "pass": output["outcomes"][case["id"]]["result"] == case["fixed"]}
              for case in cases]
    report = {"kind": "reference_transplant_not_agent_effectiveness",
              "context_identity": context["identity"], "patch_sha256": context["sha256"],
              "changed_files": context["changed_files"], "checks": checks,
              "oracle": output, "command": command, "exit_code": run.returncode}
    (evidence / "result.json").write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="ascii")
    print(json.dumps({"passed": sum(item["pass"] for item in checks), "total": len(checks)}))
    if not all(item["pass"] for item in checks):
        raise RuntimeError("reference boundary mismatch")


if __name__ == "__main__":
    main()
