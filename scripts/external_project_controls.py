"""Persist vulnerable and fixed controls for the frozen external probe."""
import json
from scripts.external_project_comparison import CACHE, EVIDENCE, PROBE, PYTHON, ROOT, invoke, save, sha


def main():
    rows = {}
    for project, version in (("cookiecutter", "2.1.1"), ("django", "3.2.14")):
        for state in ("vulnerable", "fixed"):
            target = (CACHE / "upstream" / project if state == "vulnerable" else
                      ROOT / ".validation-cache/upstream" / (project + "-" + version))
            run = invoke([PYTHON, "-B", PROBE, "--project", project, "--target", target])
            if run.returncode:
                raise ValueError(run.stderr.decode("utf-8", errors="replace"))
            result = json.loads(run.stdout)
            if state == "fixed" and result["passed"] != result["total"]:
                raise ValueError("fixed control failed")
            if state == "vulnerable" and not any(not row["pass"] for row in result["rows"] if row["role"] == "risk"):
                raise ValueError("vulnerable control did not expose risk")
            rows[project + "-" + state] = result
    save(EVIDENCE / "controls.json", {"probe_sha256": sha(PROBE), "controls": rows})
    print(json.dumps({key: [row["passed"], row["total"]] for key, row in rows.items()}))


if __name__ == "__main__":
    main()
