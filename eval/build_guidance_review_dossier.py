"""Render source, runtime, and holdout evidence for independent human review."""
import json
from pathlib import Path

from paladin.guidance import load_guidance
from paladin.knowledge import load_pack


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs/evidence/guidance-human-review.md"


def section(lines, title, values, support):
    lines.extend(["", "### " + title, ""])
    for index, value in enumerate(values):
        lines.append(f"{index + 1}. {value} [basis: {', '.join(support[index])}]")


def main():
    pack = load_pack()
    guidance = load_guidance()
    upstream = json.loads((ROOT / "docs/evidence/guidance-upstream/results.json").read_text(encoding="ascii"))
    holdout = json.loads((ROOT / "docs/evidence/guidance-holdout/results.json").read_text(encoding="ascii"))
    patched = json.loads((ROOT / "docs/evidence/guidance-patched/results.json").read_text(encoding="ascii"))
    by_id = {pattern["pattern_id"]: pattern for pattern in pack["patterns"]}
    lines = [
        "# Independent human review dossier",
        "",
        "State: pending human review. No approval or applicability verdict is recorded.",
        "Reviewer: project owner (self-selected in chat; identity record pending)",
        "Review date: [pending]",
        "Overall decision: [pending: accept / revise / reject]",
        "",
        "## Review method",
        "",
        "For each card, compare every assertion and its basis references with the pinned",
        "CVE and patch snapshots. Confirm scope, target prerequisites, correction, behavior",
        "to preserve, and test expectations. Treat inference and process markers separately",
        "from upstream source observations. Record an issue and source location for any",
        "unsupported statement. Inspect the runtime and holdout outputs independently.",
        "The probes do not execute SQL, VCS commands, network requests, or pickle loads.",
        "They test boundary behavior, not agent edit success or exploitation.",
        "",
        "## Evidence identity and aggregate result",
        "",
        f"- Guidance pack: {guidance['guidance_id']} ({guidance['review_state']}).",
        f"- Upstream version cases: {len(upstream['records'])}; status {upstream['status']}.",
        f"- Holdout manifest SHA-256: {holdout['case_manifest_sha256']}.",
        f"- Holdout: {holdout['case_count']} cases, {holdout['risk_passed']} risk and",
        f"  {holdout['safe_passed']} safe cases passed; status {holdout['status']}.",
        "- Detailed outputs: `docs/evidence/guidance-upstream/results.json` and",
        "  `docs/evidence/guidance-holdout/results.json`.",
        f"- Patched vulnerable installations: {patched['passed']}/{patched['case_count']} cases; status {patched['status']}.",
        "- Patched outputs: `docs/evidence/guidance-patched/results.json`.",
        "- Patched Django, Cookiecutter, and CPython files came from adjacent fixed releases.",
        "  BentoML received only the observed main-service HTTP guard in its vulnerable code.",
        "  File transplants may include unrelated changes. No coding-agent edit was tested.",
    ]
    for claim in guidance["claims"]:
        pattern_id = claim["pattern_id"]
        pattern = by_id[pattern_id]
        family = pattern["family"]
        lines.extend(["", "## " + pattern_id + " - " + family, "",
                      "Cause: " + pattern["cause"] + " [basis: "
                      + ", ".join(claim["support"]["cause"]) + "]", "",
                      "Source snapshots:", ""])
        for entry in pattern["evidence"]:
            lines.append("- " + entry["kind"] + ": `" + entry["snapshot_path"] + "`; SHA-256 `"
                         + entry["sha256"] + "`; " + entry["url"])
        for title, field in [("Target facts to verify", "target_facts"), ("Correction", "fix_steps"),
                             ("Behavior to preserve", "preserve"), ("Checks", "checks"),
                             ("Limitations", "limitations")]:
            section(lines, title, claim[field], claim["support"][field])
        assessed = [item for item in holdout["assessments"] if item["family"] == family]
        patched_record = patched["records"][family]
        lines.extend(["", "Holdout cases: " + ", ".join(item["id"] for item in assessed),
                      "Patched vulnerable version: " + patched_record["vulnerable_version"]
                      + "; method: " + patched_record["application_method"] + ".",
                      "Patched source SHA-256: " + patched_record["source_sha256"] + ".",
                      "", "Reviewer decision: [pending: accept / revise / reject]",
                      "Reviewer evidence and corrections: [pending]"])
    lines.extend(["", "## Final reviewer record", "",
                  "Reviewer identity: [pending]", "Review date: [pending]",
                  "Independent evidence checked: [pending]", "Final decision: [pending]",
                  "Remaining limitations: [pending]", ""])
    OUTPUT.write_text("\n".join(lines), encoding="ascii")
    print(OUTPUT)


if __name__ == "__main__":
    main()
