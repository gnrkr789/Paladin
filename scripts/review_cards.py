"""Check candidate cards against their upstream fix diffs with headless Claude Code.

Usage: python -B scripts/review_cards.py [--sample N --seed S | --all] [--workers 4]
Diffs are fetched from github.com, read for the check and dropped; each review is written to
data/cve-expansion/patch-reviews/<CVE>.json with the diff URLs and hashes only. Cards with a
review already are skipped, so reruns resume.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime
import json
from pathlib import Path
import random
import sys
import tempfile
import threading
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from headless_claude import Claude  # noqa: E402
from paladin import patch_review  # noqa: E402

DATA = ROOT / "data" / "cve-expansion"
REVIEWS = DATA / "patch-reviews"
MAX_DIFFS = 3
MAX_BYTES = 5_000_000
HOSTS = {"github.com", "patch-diff.githubusercontent.com"}


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "paladin-card-review"})
    with urllib.request.urlopen(request, timeout=30) as response:
        if urllib.parse.urlsplit(response.geturl()).hostname not in HOSTS:
            raise ValueError("redirected off GitHub")
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("diff larger than {} bytes".format(MAX_BYTES))
    return data.decode("utf-8", errors="replace")


def diffs_for(case):
    urls = list(dict.fromkeys(url for url in map(patch_review.diff_url, case["fix_references"]) if url))
    diffs, failures = [], []
    for url in urls[:MAX_DIFFS]:
        try:
            diffs.append({"url": url, "text": fetch(url)})
        except (OSError, ValueError) as exc:
            failures.append("{}: {}".format(url, type(exc).__name__))
    return diffs, failures


def main(argv=None):
    parser = argparse.ArgumentParser()
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--sample", type=int)
    scope.add_argument("--all", action="store_true")
    parser.add_argument("--seed", type=int, default=20261105)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args(argv)
    pack = json.loads((ROOT / "src" / "paladin" / "resources" / "prevention-pack.json").read_text(encoding="utf-8"))
    candidates = sorted(p["cve_id"] for p in pack["patterns"] if p["verification_status"] == "candidate")
    if args.sample:
        candidates = sorted(random.Random(args.seed).sample(candidates, args.sample))
    cases = {case["cve_id"]: case for case in json.loads((DATA / "cases.json").read_text(encoding="utf-8"))["cases"]}
    REVIEWS.mkdir(parents=True, exist_ok=True)
    todo = [cve for cve in candidates if not (REVIEWS / (cve + ".json")).exists()]
    claude, lock = Claude(), threading.Lock()

    def run(cve):
        card = json.loads((DATA / "cards" / (cve + ".json")).read_text(encoding="utf-8"))
        diffs, failures = diffs_for(cases[cve])
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as workdir:
            try:
                record = patch_review.review_card(card, diffs, lambda prompt: claude.ask(prompt, workdir))
            except Exception as exc:  # One failed card must not stop the batch; it is recorded.
                record = {"cve_id": cve, "outcome": "candidate", "reason": "run_error",
                          "errors": ["{}: {}".format(type(exc).__name__, str(exc)[:200])]}
        record.update(fetch_failures=failures, reviewer=claude.model, date=datetime.date.today().isoformat())
        (REVIEWS / (cve + ".json")).write_text(json.dumps(record, indent=1, sort_keys=True) + "\n",
                                               encoding="utf-8", newline="\n")
        with lock:
            print(cve, record["outcome"], record.get("verdict"), record.get("recheck"), record.get("reason"), flush=True)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        list(pool.map(run, todo))
    print(json.dumps({"this_run": claude.usage, "reviewed": len(todo)}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
