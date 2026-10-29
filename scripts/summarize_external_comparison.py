"""Summarize distinct contracts without converting fidelity failures to risks."""
import json
from scripts.external_project_comparison import EVIDENCE, FREEZE, save, sha


def read(path):
    return json.loads(path.read_text(encoding="ascii"))


def main():
    frozen = read(FREEZE)
    rows = []
    for project in ("cookiecutter", "django"):
        for arm in ("A", "B", "C", "D"):
            record = read(EVIDENCE / ("followup/runs/" + project + "/run.json" if arm == "D"
                                      else "runs/" + project + "-" + arm + "/run.json"))
            oracle = record["oracle"]
            row = {"project": project, "arm": arm,
                   "stage": "diagnostic_followup" if arm == "D" else "prospective_primary",
                   "primary_contract_passed": oracle["passed"], "primary_contract_total": oracle["total"]}
            if project == "cookiecutter":
                containment = read(EVIDENCE / "supplements" / (project + "-" + arm + ".json"))["result"]
                retry = "runtime-checks-retry" if arm != "D" else "runtime-checks"
                runtime = read(EVIDENCE / retry / (project + "-" + arm) / "result.json")
                row.update(containment_passed=containment["passed"], containment_total=containment["total"],
                           real_hg_passed=runtime["mercurial"]["passed"], real_hg_total=runtime["mercurial"]["total"])
            else:
                for role in ("risk", "safe"):
                    subset = [item for item in oracle["rows"] if item["role"] == role]
                    row[role + "_passed"] = sum(item["pass"] for item in subset)
                    row[role + "_total"] = len(subset)
            rows.append(row)
    save(EVIDENCE / "summary.json", {
        "kind": "descriptive_two_project_comparison_with_diagnostic_followup",
        "primary_freeze_sha256": sha(FREEZE), "projects": {key: {name: spec[name] for name in ("commit", "version", "url")}
                                                             for key, spec in frozen["projects"].items()},
        "rows": rows,
        "limits": ["Known vulnerabilities in two selected projects; not arbitrary-project prevalence or blind scanning.",
                   "Cookiecutter primary metric is strict argv fidelity, not risk containment.",
                   "D is a targeted follow-up after observing failures, not independent confirmation.",
                   "Shared filesystem and absent local complete worker traces prevent proving hidden-case secrecy.",
                   "No OS sandbox, multi-database integration or general effectiveness claim."]})
    print(json.dumps(rows))


if __name__ == "__main__":
    main()
