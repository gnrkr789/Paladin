"""Repeat supplementary compatibility checks with tested source hashes bound."""
import hashlib
import json
from scripts.external_project_comparison import CACHE, EVIDENCE, PYTHON, ROOT, invoke, manifest, save, sha


def digest_manifest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode("ascii")).hexdigest()


def main():
    for arm in ("A", "B", "C", "D"):
        key = "cookiecutter-" + arm
        target = CACHE / "tasks" / key
        record = json.loads((EVIDENCE / ("followup/runs/cookiecutter/run.json" if arm == "D"
                                        else "runs/" + key + "/run.json")).read_text(encoding="ascii"))
        for relative, expected in record["after_sha256"].items():
            if sha(target / relative) != expected:
                raise ValueError("repair source changed: " + key)
        before = manifest(target)
        directory = EVIDENCE / "bound-compatibility" / key
        directory.mkdir(parents=True, exist_ok=False)
        results = {}
        for label, script in (("containment", "external_subprocess_contract.py"),
                              ("mercurial", "external_mercurial_probe.py")):
            probe = ROOT / "eval" / script
            run = invoke([PYTHON, "-B", probe, "--target", target])
            (directory / (label + ".stdout.bin")).write_bytes(run.stdout)
            (directory / (label + ".stderr.bin")).write_bytes(run.stderr)
            if run.returncode:
                raise RuntimeError("bound compatibility check failed to execute")
            results[label] = {"probe_sha256": sha(probe), "exit_code": run.returncode,
                              "result": json.loads(run.stdout)}
        after = manifest(target)
        if before != after:
            raise ValueError("source changed during bound checks")
        save(directory / "result.json", {"key": key, "kind": "posthoc_source_bound_repeat",
                                         "tested_source_manifest_sha256": digest_manifest(before),
                                         "tested_source_manifest": before, "results": results})
        print(json.dumps({"key": key, "mercurial": results["mercurial"]["result"]["passed"],
                          "containment": results["containment"]["result"]["passed"]}))


if __name__ == "__main__":
    main()
