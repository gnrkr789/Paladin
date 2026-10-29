"""Reproduce and record safe boundary probes on pinned upstream releases."""
import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".validation-cache"
OUTPUT = ROOT / "docs/evidence/guidance-upstream/results.json"
PY39 = Path("C:/Users/user/AppData/Roaming/uv/python/cpython-3.9-windows-x86_64-none/python.exe")
PY311 = Path("C:/Users/user/AppData/Roaming/uv/python/cpython-3.11-windows-x86_64-none/python.exe")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command):
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=90, check=True)
    return {"output": json.loads(result.stdout), "stderr": result.stderr[-1000:]}


def build():
    records = {}
    for version, case in [("3.2.0", "upload"), ("3.2.1", "upload"),
                          ("3.2.13", "sql"), ("3.2.14", "sql")]:
        target = CACHE / "upstream" / ("django-" + version)
        script = ROOT / "eval/upstream_django_probe.py"
        key = "django-" + version + "-" + case
        records[key] = {**run([str(PY39), "-B", str(script), "--target", str(target), "--case", case]),
                        "probe_sha256": sha(script),
                        "source_sha256": sha(target / ("django/utils/text.py" if case == "upload"
                                                        else "django/db/models/functions/datetime.py"))}
    for version in ("2.1.0", "2.1.1"):
        target = CACHE / "upstream" / ("cookiecutter-" + version)
        script = ROOT / "eval/upstream_cookiecutter_probe.py"
        records["cookiecutter-" + version] = {
            **run([str(PY39), "-B", str(script), "--target", str(target)]),
            "probe_sha256": sha(script), "source_sha256": sha(target / "cookiecutter/vcs.py")}
    for version in ("1.2.4", "1.2.5"):
        target = CACHE / "upstream" / ("bentoml-" + version)
        script = ROOT / "eval/upstream_bentoml_probe.py"
        records["bentoml-" + version] = {
            **run([str(PY311), "-B", str(script), "--target", str(target), "--compat",
                   str(CACHE / "upstream/legacy-bento-deps")]),
            "probe_sha256": sha(script), "source_sha256": sha(target / "_bentoml_impl/server/app.py")}
    for version in ("3.9.20", "3.9.21"):
        python = CACHE / "python" / ("cpython-" + version + "-windows-x86_64-none/python.exe")
        script = ROOT / "eval/upstream_cpython_probe.py"
        records["cpython-" + version] = {
            **run([str(python), "-B", str(script)]),
            "probe_sha256": sha(script),
            "source_sha256": sha(python.parent / "Lib/urllib/parse.py"),
            "interpreter_sha256": sha(python)}
    return records


def validate(records):
    for key, record in records.items():
        package, version, *rest = key.split("-")
        observed = record["output"]
        expected_package = {"django": "Django", "cookiecutter": "cookiecutter",
                            "bentoml": "bentoml", "cpython": "CPython"}[package]
        assert observed["package"] == expected_package
        assert observed["version"] == version
        if package == "django":
            relative = "django/utils/text.py" if rest[0] == "upload" else "django/db/models/functions/datetime.py"
            source = CACHE / "upstream" / ("django-" + version) / relative
        elif package == "cookiecutter":
            source = CACHE / "upstream" / ("cookiecutter-" + version) / "cookiecutter/vcs.py"
        elif package == "bentoml":
            source = CACHE / "upstream" / ("bentoml-" + version) / "_bentoml_impl/server/app.py"
        else:
            source = CACHE / "python" / ("cpython-" + version + "-windows-x86_64-none/Lib/urllib/parse.py")
        assert Path(observed["source_file"]).resolve() == source.resolve()
        assert record["source_sha256"] == sha(source)

    def result(key, case):
        return records[key]["output"]["outcomes"][case]["result"]

    for case in ("sanitized_empty", "sanitized_parent", "parent_traversal"):
        assert result("django-3.2.0-upload", case) == "accepted"
        assert result("django-3.2.1-upload", case) == "rejected"
    for case in ("ordinary_filename", "ordinary_storage"):
        assert result("django-3.2.0-upload", case) == result("django-3.2.1-upload", case) == "accepted"
    for case in ("untrusted_trunc", "untrusted_extract"):
        assert result("django-3.2.13-sql", case) == "accepted"
        assert result("django-3.2.14-sql", case) == "rejected"
    for case in ("ordinary_trunc", "ordinary_extract"):
        assert result("django-3.2.13-sql", case) == result("django-3.2.14-sql", case) == "accepted"
    old = records["cookiecutter-2.1.0"]["output"]["outcomes"]
    new = records["cookiecutter-2.1.1"]["output"]["outcomes"]
    assert old["hg:--config=harmless"][1] == ["hg", "checkout", "--config=harmless"]
    assert new["hg:--config=harmless"][1] == ["hg", "checkout", "--", "--config=harmless"]
    assert new["hg:stable"][1] == ["hg", "checkout", "--", "stable"]
    assert new["git:stable"][1] == old["git:stable"][1] == ["git", "checkout", "stable"]
    for case in ("bracketed_ipv4", "invalid_bracketed_host"):
        assert result("cpython-3.9.20", case) == "accepted"
        assert result("cpython-3.9.21", case) == "rejected"
    for case in ("valid_ipv6", "valid_ipvfuture"):
        assert result("cpython-3.9.20", case) == result("cpython-3.9.21", case) == "accepted"
    assert result("bentoml-1.2.4", "main_pickle") == "reached_serde"
    assert result("bentoml-1.2.5", "main_pickle") == "rejected_before_serde"
    assert records["bentoml-1.2.5"]["output"]["outcomes"]["main_pickle"]["error_code"] == 415
    for case in ("main_json", "internal_pickle"):
        assert result("bentoml-1.2.4", case) == result("bentoml-1.2.5", case) == "reached_serde"


def main():
    records = build()
    validate(records)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps({"status": "PASS", "scope": "upstream_boundary_not_exploit_or_agent_effectiveness",
                                  "records": records}, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print(json.dumps({"status": "PASS", "version_cases": len(records), "output": str(OUTPUT)}))


if __name__ == "__main__":
    main()
