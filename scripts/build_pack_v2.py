"""Build prevention pack v2 from drafted cards and copy their pinned evidence.

Usage: python -B scripts/build_pack_v2.py PYSEC GHSA CVELIST [--date YYYY-MM-DD]
Writes src/paladin/resources/prevention-pack.json and its lock, records cards whose CVE is
no longer collected in data/cve-expansion/withdrawn.json (kept out of the pack), and copies advisory and
CVE files to data/cve-expansion/sources/. Regenerate the vector snapshot afterwards with
`paladin patterns export`.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from paladin import knowledge, pack_build  # noqa: E402

DATA = ROOT / "data" / "cve-expansion"
RESOURCES = ROOT / "src" / "paladin" / "resources"
BASE_REF = "734695d"  # last commit with the verified-only v1 pack; its order is kept
BASE_PATH = "src/paladin/resources/prevention-pack.json"


def main(argv=None):
    parser = argparse.ArgumentParser()
    for name in ("pysec", "ghsa", "cvelist"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--date", default=datetime.date.today().isoformat())
    parser.add_argument("--base-ref", default=BASE_REF, help="commit holding the verified v1 pack")
    args = parser.parse_args(argv)
    roots = {name: getattr(args, name) for name in ("pysec", "ghsa", "cvelist")}
    collection = json.loads((DATA / "cases.json").read_text(encoding="utf-8"))
    pins = collection["sources"]
    withdrawn_path = DATA / "withdrawn.json"
    history = json.loads(withdrawn_path.read_text(encoding="utf-8")) if withdrawn_path.exists() else []
    base = json.loads(subprocess.run(["git", "-C", str(ROOT), "show", args.base_ref + ":" + BASE_PATH], check=True,
                                     capture_output=True).stdout)
    known = {pattern["cve_id"] for pattern in base["patterns"]}
    cards = [card for card in (json.loads(path.read_text(encoding="utf-8"))
                               for path in sorted((DATA / "cards").glob("CVE-*.json")))
             if card["cve_id"] not in known]
    cards, withdrawn = pack_build.split_withdrawn(cards, collection, history, args.date)
    withdrawn_path.write_text(json.dumps(withdrawn, indent=1) + "\n", encoding="utf-8", newline="\n")
    pairs = [(card, pack_build.copy_evidence(card, roots, pins, ROOT, "data/cve-expansion/sources"))
             for card in cards]
    pack = knowledge.validate_pack(pack_build.build_pack(base, pairs, args.date))
    raw = (json.dumps(pack, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    (RESOURCES / "prevention-pack.json").write_bytes(raw)
    lock = {"pack_id": pack["pack_id"], "sha256": hashlib.sha256(raw).hexdigest(),
            "pattern_count": len(pack["patterns"])}
    (RESOURCES / "prevention-pack.lock.json").write_bytes(json.dumps(lock, indent=2).replace("\n", "\r\n").encode()
                                                          + b"\r\n")
    print(json.dumps({"patterns": len(pack["patterns"]), "candidates": sum(
        p["verification_status"] == "candidate" for p in pack["patterns"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
