"""Merge drafted rules, record their first held-out scan, and ship runtime rule data.

Usage: python -B scripts/build_rules.py CORPUS_DIR [CORPUS_DIR ...]
The corpus is real Python code the rules were not drafted against (for example an
installed site-packages); its first scan is the honest noise figure and is recorded,
never tuned against. Writes data/cve-expansion/rules.json (with examples and scan
counts) and src/paladin/resources/change-rules.json (matchers only).
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from paladin import data_rules, rule_draft  # noqa: E402

DATA = ROOT / "data" / "cve-expansion"
MAX_BYTES = 1_000_000


def corpus_scan(rules, roots):
    compiled = data_rules.compile_rules(rules)
    hits = {rule["rule_id"]: {"findings": 0, "files": 0} for rule in rules}
    files = 0
    for root in roots:
        for path in sorted(Path(root).rglob("*.py")):
            try:
                if not path.is_file() or path.stat().st_size > MAX_BYTES:
                    continue
                findings, _ = data_rules.scan(compiled, path.read_bytes())
            except (OSError, RecursionError, MemoryError):
                continue
            files += 1
            for rule_id in {finding["rule_id"] for finding in findings}:
                hits[rule_id]["files"] += 1
            for finding in findings:
                hits[finding["rule_id"]]["findings"] += 1
    return files, hits


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus", nargs="+", type=Path)
    args = parser.parse_args(argv)
    drafts = [json.loads(path.read_text(encoding="utf-8")) for path in sorted((DATA / "rule-drafts").glob("*.json"))]
    rules = [draft["rule"] for draft in drafts if draft["rule"] and not data_rules.validate_rule(draft["rule"])]
    merged = rule_draft.merge_rules(rules)
    files, hits = corpus_scan(merged, args.corpus)
    record = {"schema_version": 1, "drafts": len(drafts), "no_rule": sum(1 for d in drafts if d["no_rule"]),
              "valid_rules": len(rules), "merged_rules": len(merged),
              "first_heldout_scan": {"corpus": [path.as_posix() for path in args.corpus], "files": files,
                                     "per_rule": hits},
              "rules": merged}
    (DATA / "rules.json").write_text(json.dumps(record, indent=1, sort_keys=True) + "\n", encoding="utf-8",
                                     newline="\n")
    runtime = {"schema_version": 1,
               "rules": [{key: value for key, value in rule.items() if key != "examples"} for rule in merged]}
    data_rules.load_runtime(runtime)
    (ROOT / "src" / "paladin" / "resources" / "change-rules.json").write_text(
        json.dumps(runtime, indent=1, sort_keys=True) + "\n", encoding="ascii", newline="\n")
    noisy = sorted(((v["files"], k) for k, v in hits.items() if v["files"]), reverse=True)[:15]
    print(json.dumps({k: v for k, v in record.items() if k not in ("rules", "first_heldout_scan")}, indent=1))
    print("corpus files:", files, "noisiest rules (files hit):", noisy)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
