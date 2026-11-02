"""Draft change-check rules from accepted cards with headless Claude Code (offline research).

Usage: python -B scripts/draft_rules.py [--limit N] [--workers 6]
Per-CVE answers go to data/cve-expansion/rule-drafts/<CVE>.json (a rule, or no rule with a
reason); cases already answered are skipped, so reruns resume. Merging and the held-out
scan run separately (scripts/build_rules.py).
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from headless_claude import Claude  # noqa: E402
from paladin import rule_draft  # noqa: E402

DATA = ROOT / "data" / "cve-expansion"


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int)
    parser.add_argument("--workers", type=int, default=6)
    args = parser.parse_args(argv)
    out = DATA / "rule-drafts"
    out.mkdir(parents=True, exist_ok=True)
    cards = [json.loads(path.read_text(encoding="utf-8")) for path in sorted((DATA / "cards").glob("CVE-*.json"))
             if not (out / path.name).exists()][:args.limit]
    claude = Claude()

    def run(card):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as workdir:
            try:
                result = rule_draft.draft_rule(card, lambda prompt: claude.ask(prompt, workdir))
            except Exception as exc:  # Reported per card; the batch continues.
                result = {"rule": None, "no_rule": None, "attempts": 0, "last_answer": None,
                          "errors": ["run: {}: {}".format(type(exc).__name__, exc)]}
        if result["rule"] or result["no_rule"]:
            (out / (card["cve_id"] + ".json")).write_text(json.dumps(dict(result, model=claude.model), indent=1,
                                                                      sort_keys=True) + "\n",
                                                          encoding="utf-8", newline="\n")
        else:  # Rejected: kept apart for diagnosis; the case is retried on the next run.
            (out / "rejected").mkdir(exist_ok=True)
            (out / "rejected" / (card["cve_id"] + ".json")).write_text(
                json.dumps(result, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        state = "rule" if result["rule"] else "no_rule" if result["no_rule"] else "rejected"
        print(card["cve_id"], state, "; ".join(result["errors"])[:200], flush=True)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        list(pool.map(run, cards))
    print(json.dumps(claude.usage, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
