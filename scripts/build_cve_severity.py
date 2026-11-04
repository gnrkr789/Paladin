"""Build the packaged CVE severity index for the pack CVEs.

Usage: python -B scripts/build_cve_severity.py GHSA CVELIST
Reads each collected case's GHSA advisory and CVE record at the hashes the collector
recorded; CVEs outside the collected cases (the first verified cards) use their pinned
CVE record copy in the evidence. Writes src/paladin/resources/cve-severity.json.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from paladin import knowledge, severity  # noqa: E402
from paladin.card_draft import _pinned  # noqa: E402

DATA = ROOT / "data" / "cve-expansion"


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("ghsa", type=Path)
    parser.add_argument("cvelist", type=Path)
    args = parser.parse_args(argv)
    pack = {p["cve_id"]: p for p in knowledge.load_pack()["patterns"]}
    cases = {case["cve_id"]: case for case in json.loads((DATA / "cases.json").read_text(encoding="utf-8"))["cases"]}
    levels = {}
    for cve, pattern in sorted(pack.items()):
        case, level, source = cases.get(cve), None, None
        for advisory in (case or {}).get("advisories", []):
            if advisory["source"] == "ghsa":
                record = json.loads(_pinned(args.ghsa, advisory["path"], advisory["sha256"]))
                level, source = severity.from_ghsa(record), advisory["id"]
                if level:
                    break
        if not level and case:
            record = json.loads(_pinned(args.cvelist, case["cve_record"]["path"], case["cve_record"]["sha256"]))
            level, source = severity.from_cve_record(record), cve + " CVSS"
        if not level:
            for entry in pattern["evidence"]:
                if entry["kind"] == "cve":
                    record = json.loads((ROOT / entry["snapshot_path"]).read_bytes())
                    level, source = severity.from_cve_record(record), cve + " CVSS"
                    break
        if level:
            levels[cve] = {"severity": level, "source": source}
    index = {"schema_version": 1, "note": "GHSA severity (MODERATE as MEDIUM), else CVSS base severity of the CVE "
                                          "record; MEDIUM and above block, LOW is opt-in.", "levels": levels}
    path = ROOT / "src" / "paladin" / "resources" / severity.RESOURCE
    path.write_text(json.dumps(index, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    counts = {level: sum(1 for item in levels.values() if item["severity"] == level) for level in severity.LEVELS}
    print(json.dumps({"pack_cves": len(pack), "with_severity": len(levels), "counts": counts,
                      "without": sorted(set(pack) - set(levels))}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
