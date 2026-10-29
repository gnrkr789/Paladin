"""Run a frozen 20-case upstream boundary holdout on vulnerable/fixed releases."""
import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".validation-cache"
CASES = ROOT / "eval/guidance_holdout_cases.json"
PROBE = ROOT / "eval/guidance_holdout_probe.py"
OUTPUT = ROOT / "docs/evidence/guidance-holdout/results.json"
CASES_SHA256 = "4c918c59a7dbebc1ee3e94f34272fc9e42c7a3c91e6e9c6ff478666575d79df8"
PY39 = Path("C:/Users/user/AppData/Roaming/uv/python/cpython-3.9-windows-x86_64-none/python.exe")
PY311 = Path("C:/Users/user/AppData/Roaming/uv/python/cpython-3.11-windows-x86_64-none/python.exe")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(python, family, target=None, compat=None):
    command = [str(python), "-B", str(PROBE), "--cases", str(CASES), "--family", family]
    if target:
        command += ["--target", str(target)]
    if compat:
        command += ["--compat", str(compat)]
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=90, check=True)
    return {"output": json.loads(completed.stdout), "stderr": completed.stderr[-1000:]}


def verify_identity(record, family, python, target, version):
    package, relative = {
        "path_traversal": ("Django", "django/utils/text.py"),
        "sql_injection": ("Django", "django/db/models/functions/datetime.py"),
        "ssrf": ("CPython", "Lib/urllib/parse.py"),
        "command_injection": ("cookiecutter", "cookiecutter/vcs.py"),
        "unsafe_deserialization": ("bentoml", "_bentoml_impl/server/app.py"),
    }[family]
    source = (target if target is not None else python.parent) / relative
    observed = record["output"]
    assert observed["family"] == family
    assert observed["package"] == package
    assert observed["version"] == version
    assert Path(observed["source_file"]).resolve() == source.resolve()
    record["source_sha256"] = sha(source)
    record["interpreter_sha256"] = sha(python)


def main():
    if sha(CASES) != CASES_SHA256:
        raise ValueError("holdout case manifest changed")
    cases = json.loads(CASES.read_text(encoding="ascii"))["cases"]
    if len(cases) != 20 or len({case["id"] for case in cases}) != 20:
        raise ValueError("holdout must contain twenty unique cases")
    pairs = {
        "path_traversal": (
            (PY39, CACHE / "upstream/django-3.2.0", None),
            (PY39, CACHE / "upstream/django-3.2.1", None)),
        "sql_injection": (
            (PY39, CACHE / "upstream/django-3.2.13", None),
            (PY39, CACHE / "upstream/django-3.2.14", None)),
        "ssrf": (
            (CACHE / "python/cpython-3.9.20-windows-x86_64-none/python.exe", None, None),
            (CACHE / "python/cpython-3.9.21-windows-x86_64-none/python.exe", None, None)),
        "command_injection": (
            (PY39, CACHE / "upstream/cookiecutter-2.1.0", None),
            (PY39, CACHE / "upstream/cookiecutter-2.1.1", None)),
        "unsafe_deserialization": (
            (PY311, CACHE / "upstream/bentoml-1.2.4", CACHE / "upstream/legacy-bento-deps"),
            (PY311, CACHE / "upstream/bentoml-1.2.5", CACHE / "upstream/legacy-bento-deps")),
    }
    outputs = {}
    assessments = []
    expected_versions = {
        "path_traversal": ("3.2.0", "3.2.1"),
        "sql_injection": ("3.2.13", "3.2.14"),
        "ssrf": ("3.9.20", "3.9.21"),
        "command_injection": ("2.1.0", "2.1.1"),
        "unsafe_deserialization": ("1.2.4", "1.2.5"),
    }
    for family, (vulnerable, fixed) in pairs.items():
        outputs[family] = {"vulnerable": run(vulnerable[0], family, vulnerable[1], vulnerable[2]),
                           "fixed": run(fixed[0], family, fixed[1], fixed[2])}
        for label, spec, expected_version in zip(("vulnerable", "fixed"),
                                                 (vulnerable, fixed), expected_versions[family]):
            verify_identity(outputs[family][label], family, spec[0], spec[1], expected_version)
        old = outputs[family]["vulnerable"]["output"]["outcomes"]
        new = outputs[family]["fixed"]["output"]["outcomes"]
        if family == "unsafe_deserialization":
            for case_id in ("DESER-R1", "DESER-R2"):
                assert new[case_id]["error_code"] == 415
        for case in (item for item in cases if item["family"] == family):
            observed_old = old[case["id"]]["result"]
            observed_new = new[case["id"]]["result"]
            assessments.append({"id": case["id"], "family": family, "role": case["role"],
                                "expected_vulnerable": case["vulnerable"],
                                "expected_fixed": case["fixed"],
                                "observed_vulnerable": observed_old,
                                "observed_fixed": observed_new,
                                "pass": observed_old == case["vulnerable"] and observed_new == case["fixed"]})
    status = "PASS" if all(item["pass"] for item in assessments) else "FAIL"
    result = {"status": status, "scope": "upstream_boundary_not_agent_success",
              "case_manifest_sha256": CASES_SHA256, "probe_sha256": sha(PROBE),
              "case_count": len(assessments),
              "risk_passed": sum(item["pass"] for item in assessments if item["role"] == "risk"),
              "safe_passed": sum(item["pass"] for item in assessments if item["role"] == "safe"),
              "assessments": assessments, "outputs": outputs}
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print(json.dumps({"status": status, "case_count": result["case_count"],
                      "risk_passed": result["risk_passed"], "safe_passed": result["safe_passed"],
                      "output": str(OUTPUT)}))
    if status != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
