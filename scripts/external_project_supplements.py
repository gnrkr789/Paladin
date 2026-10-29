"""Persist supplementary containment, source identities and Hg controls."""
import json
from scripts.external_project_comparison import CACHE, EVIDENCE, PYTHON, ROOT, invoke, manifest, save, sha


def main():
    probe = ROOT / "eval/external_subprocess_contract.py"
    for arm in ("A", "B", "C", "D"):
        key = "cookiecutter-" + arm
        run = invoke([PYTHON, "-B", probe, "--target", CACHE / "tasks" / key])
        if run.returncode:
            raise RuntimeError(run.stderr.decode("utf-8", errors="replace"))
        save(EVIDENCE / "supplements" / (key + ".json"), {"probe_sha256": sha(probe), "result": json.loads(run.stdout)})
    hg_probe = ROOT / "eval/external_mercurial_probe.py"
    controls = {}
    for label, target in (("vulnerable", CACHE / "upstream/cookiecutter"),
                          ("fixed", ROOT / ".validation-cache/upstream/cookiecutter-2.1.1")):
        run = invoke([PYTHON, "-B", hg_probe, "--target", target])
        if run.returncode:
            raise RuntimeError(run.stderr.decode("utf-8", errors="replace"))
        controls[label] = json.loads(run.stdout)
    identities = {project: manifest(ROOT / ".validation-cache/upstream" / name)
                  for project, name in (("cookiecutter", "cookiecutter-2.1.1"), ("django", "django-3.2.14"))}
    save(EVIDENCE / "supplements/controls-and-identities.json", {
        "kind": "posthoc_control_identity_snapshot", "mercurial_controls": controls,
        "mercurial_probe_sha256": sha(hg_probe), "mercurial_runtime": manifest(CACHE / "hg-runtime"),
        "fixed_control_sources": identities})
    print("SUPPLEMENTARY_CHECKS_SAVED")


if __name__ == "__main__":
    main()
