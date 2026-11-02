"""Draft prevention cards for collected CVE cases with headless Claude Code (offline research).

Usage: python -B scripts/draft_cards.py PYSEC GHSA CVELIST [--limit N] [--workers 4]
Accepted cards go to data/cve-expansion/cards/<CVE>.json; every attempt is summarized in
data/cve-expansion/draft-report.json. Cases with a card already are skipped, so reruns resume.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from headless_claude import Claude  # noqa: E402
from paladin import card_draft  # noqa: E402

DATA = ROOT / "data" / "cve-expansion"


def main(argv=None):
    parser = argparse.ArgumentParser()
    for name in ("pysec", "ghsa", "cvelist"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args(argv)
    roots = {name: getattr(args, name) for name in ("pysec", "ghsa", "cvelist")}
    cards = DATA / "cards"
    cards.mkdir(parents=True, exist_ok=True)
    report_path = DATA / "draft-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {"cases": {}}
    cases = [case for case in json.loads((DATA / "cases.json").read_text(encoding="utf-8"))["cases"]
             if not (cards / (case["cve_id"] + ".json")).exists()][:args.limit]
    claude, lock = Claude(), threading.Lock()

    def run(case):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as workdir:
            try:
                sources = card_draft.source_texts(case, roots)
                result = card_draft.draft_case(case, sources, lambda prompt: claude.ask(prompt, workdir))
            except Exception as exc:  # One failed case must not stop the batch; it is reported.
                result = {"draft": None, "attempts": 0, "errors": ["run: {}: {}".format(type(exc).__name__, exc)]}
        if result["draft"]:
            card = card_draft.to_card(result["draft"], case, drafter=claude.model)
            (cards / (case["cve_id"] + ".json")).write_text(json.dumps(card, indent=1, sort_keys=True) + "\n",
                                                            encoding="utf-8", newline="\n")
        with lock:
            report["cases"][case["cve_id"]] = {"accepted": bool(result["draft"]), "attempts": result["attempts"],
                                               "errors": result["errors"]}
            print("{} {}".format(case["cve_id"], "ok" if result["draft"] else "rejected"), flush=True)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        list(pool.map(run, cases))
    report["cases"] = dict(sorted(report["cases"].items()))
    report["accepted"] = sum(1 for item in report["cases"].values() if item["accepted"])
    report["model"] = claude.model
    report_path.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"this_run": claude.usage, "accepted_total": report["accepted"],
                      "cases_total": len(report["cases"])}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
