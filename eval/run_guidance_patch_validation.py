"""Test fixed-release source transplants in isolated vulnerable installations."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".validation-cache"
CASES = ROOT / "eval/guidance_holdout_cases.json"
PROBE = ROOT / "eval/guidance_holdout_probe.py"
OUTPUT = ROOT / "docs/evidence/guidance-patched/results.json"
PY39 = Path("C:/Users/user/AppData/Roaming/uv/python/cpython-3.9-windows-x86_64-none/python.exe")
PY311 = Path("C:/Users/user/AppData/Roaming/uv/python/cpython-3.11-windows-x86_64-none/python.exe")
CASE_SHA256 = "4c918c59a7dbebc1ee3e94f34272fc9e42c7a3c91e6e9c6ff478666575d79df8"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


PAIRS = {
    "path_traversal": ("django", "3.2.0", "3.2.1", [
        "django/core/files/storage.py", "django/core/files/uploadedfile.py",
        "django/core/files/utils.py", "django/db/models/fields/files.py",
        "django/http/multipartparser.py", "django/utils/text.py"]),
    "sql_injection": ("django", "3.2.13", "3.2.14", [
        "django/db/backends/base/operations.py", "django/db/models/functions/datetime.py"]),
    "command_injection": ("cookiecutter", "2.1.0", "2.1.1", ["cookiecutter/vcs.py"]),
    "unsafe_deserialization": ("bentoml", "1.2.4", "1.2.5", ["_bentoml_impl/server/app.py"]),
    "ssrf": ("cpython", "3.9.20", "3.9.21", ["Lib/urllib/parse.py"]),
}


def prepare(family):
    package, vulnerable_version, fixed_version, files = PAIRS[family]
    if package == "cpython":
        vulnerable = CACHE / "python" / ("cpython-" + vulnerable_version + "-windows-x86_64-none")
        fixed = CACHE / "python" / ("cpython-" + fixed_version + "-windows-x86_64-none")
        target = CACHE / "patched" / ("cpython-" + vulnerable_version) / "overlay"
        if not target.exists():
            shutil.copytree(vulnerable / "Lib/urllib", target / "urllib")
        destination = target / "urllib/parse.py"
        original = vulnerable / "Lib/urllib/parse.py"
        replacement = fixed / "Lib/urllib/parse.py"
        shutil.copy2(replacement, destination)
        assert sha(destination) == sha(replacement)
        changes = [{"path": "urllib/parse.py", "vulnerable_sha256": sha(original),
                    "fixed_sha256": sha(replacement), "patched_sha256": sha(destination)}]
        return vulnerable / "python.exe", None, target, destination, changes
    vulnerable = CACHE / "upstream" / (package + "-" + vulnerable_version)
    fixed = CACHE / "upstream" / (package + "-" + fixed_version)
    target = CACHE / "patched" / (package + "-" + vulnerable_version + "-" + family + "-focused")
    if not target.exists():
        shutil.copytree(vulnerable, target)
    changes = []
    for relative in files:
        original, replacement, destination = vulnerable / relative, fixed / relative, target / relative
        if package == "bentoml":
            content = original.read_text(encoding="utf-8")
            content = content.replace("import functools\n", "import functools\nfrom http import HTTPStatus\n", 1)
            anchor = '        media_type = media_type.split(";")[0].strip()\n'
            guard = ('        if self.is_main and media_type == "application/vnd.bentoml+pickle":\n'
                     '            raise BentoMLException(\n'
                     '                "Pickle media type is not allowed for main service",\n'
                     '                error_code=HTTPStatus.UNSUPPORTED_MEDIA_TYPE,\n'
                     '            )\n')
            assert content.count(anchor) == 1
            content = content.replace(anchor, anchor + guard, 1)
            destination.write_text(content, encoding="utf-8")
        else:
            shutil.copy2(replacement, destination)
            assert sha(destination) == sha(replacement)
        changes.append({"path": relative, "vulnerable_sha256": sha(original),
                        "fixed_sha256": sha(replacement), "patched_sha256": sha(destination)})
    source_relative = {"path_traversal": "django/utils/text.py",
                       "sql_injection": "django/db/models/functions/datetime.py",
                       "command_injection": "cookiecutter/vcs.py",
                       "unsafe_deserialization": "_bentoml_impl/server/app.py"}[family]
    return PY311 if package == "bentoml" else PY39, target, None, target / source_relative, changes


def probe(python, family, target, overlay):
    command = [str(python), "-B", str(PROBE), "--cases", str(CASES), "--family", family]
    if target:
        command += ["--target", str(target)]
    if family == "unsafe_deserialization":
        command += ["--compat", str(CACHE / "upstream/legacy-bento-deps")]
    env = os.environ.copy()
    if overlay:
        env["PYTHONPATH"] = str(overlay)
    completed = subprocess.run(command, cwd=ROOT, env=env, capture_output=True,
                               text=True, timeout=90, check=True)
    return json.loads(completed.stdout)


def main():
    if sha(CASES) != CASE_SHA256:
        raise ValueError("holdout case manifest changed")
    cases = json.loads(CASES.read_text(encoding="ascii"))["cases"]
    records = {}
    for family in PAIRS:
        python, target, overlay, source, changes = prepare(family)
        output = probe(python, family, target, overlay)
        package, vulnerable_version, _, _ = PAIRS[family]
        assert output["version"] == vulnerable_version
        assert output["package"].lower() == package
        assert Path(output["source_file"]).resolve() == source.resolve()
        assert sha(source) in [item["patched_sha256"] for item in changes]
        family_cases = [case for case in cases if case["family"] == family]
        if family == "unsafe_deserialization":
            for case in family_cases:
                if case["role"] == "risk":
                    assert output["outcomes"][case["id"]]["error_code"] == 415
        assessments = [{"id": case["id"], "role": case["role"],
                        "observed": output["outcomes"][case["id"]]["result"],
                        "expected": case["fixed"],
                        "pass": output["outcomes"][case["id"]]["result"] == case["fixed"]}
                       for case in family_cases]
        records[family] = {"vulnerable_version": vulnerable_version,
                           "application_method": "focused_guard" if family == "unsafe_deserialization"
                           else "fixed_release_source_transplant",
                           "source_file": str(source.resolve()), "source_sha256": sha(source),
                           "interpreter_sha256": sha(python), "transplanted_files": changes,
                           "assessments": assessments, "output": output}
    all_assessments = [assessment for record in records.values() for assessment in record["assessments"]]
    status = "PASS" if len(all_assessments) == 20 and all(item["pass"] for item in all_assessments) else "FAIL"
    result = {"status": status, "scope": "fixed_release_source_transplant_in_vulnerable_installations",
              "limitations": ["Adjacent fixed-release files may include unrelated changes.",
                              "These are boundary probes, not end-to-end exploits or agent edits."],
              "case_manifest_sha256": CASE_SHA256, "probe_sha256": sha(PROBE),
              "case_count": len(all_assessments), "passed": sum(item["pass"] for item in all_assessments),
              "records": records}
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print(json.dumps({"status": status, "case_count": result["case_count"],
                      "passed": result["passed"], "output": str(OUTPUT)}))
    if status != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
