"""Collect the CVE expansion case list from local PYSEC, GHSA and cvelistV5 checkouts.

Usage: python -B scripts/collect_cves.py PYSEC GHSA CVELIST [--out data/cve-expansion/cases.json]
Each checkout's HEAD commit is recorded as its pin. --missing prints the cvelistV5 paths
still needed (for a sparse checkout) instead of writing the case list.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from paladin import cve_collect  # noqa: E402

PACKAGES = ROOT / "data" / "cve-expansion" / "packages.json"


def head(path):
    return subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], check=True,
                          capture_output=True, text=True).stdout.strip()


def main(argv=None):
    parser = argparse.ArgumentParser()
    for name in ("pysec", "ghsa", "cvelist"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--out", type=Path, default=ROOT / "data" / "cve-expansion" / "cases.json")
    parser.add_argument("--missing", action="store_true")
    args = parser.parse_args(argv)
    packages = json.loads(PACKAGES.read_text(encoding="utf-8"))["packages"]
    pins = {name: head(getattr(args, name)) for name in ("pysec", "ghsa", "cvelist")}
    result = cve_collect.collect(args.pysec, args.ghsa, args.cvelist, packages, pins)
    if args.missing:
        ids = sorted({item["cve_id"] for item in result["skipped_items"] if item["reason"] == "cve_record_missing"})
        print("\n".join(cve_collect.cve_record_path(cve_id) for cve_id in ids))
        return 0
    args.out.write_text(json.dumps(result, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"cases": len(result["cases"]), "family_counts": result["family_counts"],
                      "skipped": result["skipped"]}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
