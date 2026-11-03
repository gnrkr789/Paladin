"""Build the packaged dependency advisory index from the pinned PYSEC and GHSA records.

Usage: python -B scripts/build_dependency_index.py PYSEC GHSA
Reads each collected case's advisories at the hashes the collector recorded, keeps PyPI
ECOSYSTEM ranges (or explicit versions) for CVEs in the prevention pack, and writes
src/paladin/resources/dependency-advisories.json. CVEs whose advisories name no PyPI
range or version are counted, not guessed.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from paladin import dependency_check, knowledge  # noqa: E402
from paladin.card_draft import _pinned  # noqa: E402
from paladin.cve_collect import load_yaml  # noqa: E402

DATA = ROOT / "data" / "cve-expansion"


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("pysec", type=Path)
    parser.add_argument("ghsa", type=Path)
    args = parser.parse_args(argv)
    roots = {"pysec": args.pysec, "ghsa": args.ghsa}
    collection = json.loads((DATA / "cases.json").read_text(encoding="utf-8"))
    titles = {p["cve_id"]: p["title"] for p in knowledge.load_pack()["patterns"]}
    merged = {}
    for case in collection["cases"]:
        if case["cve_id"] not in titles:
            continue
        for advisory in case["advisories"]:
            data = _pinned(roots[advisory["source"]], advisory["path"], advisory["sha256"])
            record = load_yaml(data) if advisory["source"] == "pysec" else json.loads(data)
            for entry in dependency_check.affected_entries(record):
                key = (case["cve_id"], entry["package"])
                target = merged.setdefault(key, {"cve_id": case["cve_id"], "package": entry["package"],
                                                 "title": titles[case["cve_id"]], "ranges": [], "versions": []})
                target["ranges"] += [pair for pair in entry["ranges"] if pair not in target["ranges"]]
                target["versions"] = sorted(set(target["versions"]) | set(entry["versions"]))
    entries = [entry for entry in sorted(merged.values(), key=lambda e: (e["cve_id"], e["package"]))
               if entry["ranges"] or entry["versions"]]
    covered = {entry["cve_id"] for entry in entries}
    index = {"schema_version": 1, "sources": {key: collection["sources"][key] for key in ("pysec", "ghsa")},
             "note": "PyPI affected ranges from PYSEC and GHSA (CC-BY-4.0) for CVEs in the prevention pack.",
             "entries": entries}
    path = ROOT / "src" / "paladin" / "resources" / dependency_check.RESOURCE
    path.write_text(json.dumps(index, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"entries": len(entries), "cves": len(covered), "pack_cves": len(titles),
                      "pack_cves_without_ranges": len(set(titles) - covered)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
