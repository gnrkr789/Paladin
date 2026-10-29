"""Confirm preserved legacy records can be superseded by verified revisions."""
import json
from pathlib import Path
import shutil

from paladin.case_pipeline import run_case, verified_case_references
from paladin.case_store import list_cases, promote_case
from scripts.verify_cve_case_loop_final import CACHE, EVIDENCE, ROOT, command, digest


def main():
    output = EVIDENCE / "policy-final"
    (output / "implementation").mkdir(parents=True, exist_ok=False)
    hashes = {}
    for source in (ROOT / "src/paladin").glob("*.py"):
        shutil.copy2(source, output / "implementation" / source.name)
        hashes[source.name] = digest(source)
    (output / "implementation.json").write_text(json.dumps(hashes, indent=2, sort_keys=True), encoding="ascii")
    original = json.loads((ROOT / "docs/evidence/cve-case-loop-v2/result.json").read_text(encoding="ascii"))["promoted_case"]
    result = command("positive-final-policy", "auto", CACHE / "source")
    current = next(row["case"] for row in result["case_runs"] if row["status"] == "promoted")
    if current["case_id"] != original["case_id"]:
        raise ValueError("primary_case_identity_changed")
    workspace = CACHE / "legacy-upgrade-workspace"
    (workspace / ".paladin/case-evidence").mkdir(parents=True)
    legacy = {key: value for key, value in original.items() if key != "case_id"}
    legacy["verifier_id"] = "mercurial-checkout-local-probe-v1"
    old = promote_case(workspace / ".paladin/cases.sqlite3", legacy)
    refs_before = verified_case_references(workspace, "CVE-2022-24065")
    if refs_before["cases"]:
        raise ValueError("legacy_record_exposed")
    new = run_case(workspace, CACHE / "source", original["candidate_id"])
    rows = list_cases(workspace / ".paladin/cases.sqlite3")
    refs_after = verified_case_references(workspace, "CVE-2022-24065")
    if (new["status"] != "promoted" or len(rows) != 2 or old not in rows
            or len(refs_after["cases"]) != 1
            or refs_after["cases"][0]["case_id"] != new["case"]["case_id"]):
        raise ValueError("legacy_upgrade_policy_failed")
    record = {"primary_case_identity_stable": True, "legacy_record_exposed_before": False,
              "legacy_record_preserved": True, "stored_revision_count": len(rows),
              "reusable_revision_count": len(refs_after["cases"]),
              "legacy_status": refs_after["status"], "current_verifier": new["case"]["verifier_id"]}
    (output / "result.json").write_text(json.dumps(record, indent=2, sort_keys=True), encoding="ascii")
    print(json.dumps(record))


if __name__ == "__main__":
    main()
