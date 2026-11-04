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

from paladin import data_rules, rule_draft, severity  # noqa: E402

DATA = ROOT / "data" / "cve-expansion"
MAX_BYTES = 1_000_000
# A rule that fires in more corpus files than this on its first scan is too noisy to ship.
# It stays in rules.json under not_shipped, with its scan count, and is never tuned to pass.
MAX_FILES_HIT = 50


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
    # A redraft from the patch-checked pack text (rule-drafts-v2) replaces the first answer.
    answers = {path.stem: path for path in sorted((DATA / "rule-drafts").glob("*.json"))}
    answers.update({path.stem: path for path in sorted((DATA / "rule-drafts-v2").glob("*.json"))})
    drafts = [json.loads(answers[key].read_text(encoding="utf-8")) for key in sorted(answers)]
    rules = [draft["rule"] for draft in drafts if draft["rule"] and not data_rules.validate_rule(draft["rule"])]
    merged = rule_draft.merge_rules(rules)
    files, hits = corpus_scan(merged, args.corpus)
    shipped = [rule for rule in merged if hits[rule["rule_id"]]["files"] <= MAX_FILES_HIT]
    record = {"schema_version": 1, "drafts": len(drafts), "no_rule": sum(1 for d in drafts if d["no_rule"]),
              "valid_rules": len(rules), "merged_rules": len(merged), "shipped_rules": len(shipped),
              "max_files_hit": MAX_FILES_HIT,
              "first_heldout_scan": {"corpus": [path.as_posix() for path in args.corpus], "files": files,
                                     "per_rule": hits},
              "not_shipped": [rule["rule_id"] for rule in merged if rule not in shipped],
              "rules": merged}
    (DATA / "rules.json").write_text(json.dumps(record, indent=1, sort_keys=True) + "\n", encoding="utf-8",
                                     newline="\n")
    # Severity criterion (user, 2026-11-04): a rule's highest CVE severity decides; MEDIUM and
    # above block, LOW and unknown advise (LOW blocks only with hook install --block-low).
    levels = {cve: item["severity"] for cve, item in severity.load_index()["levels"].items()}
    runtime_rules = []
    for rule in shipped:
        level = severity.rule_level(rule["cve_ids"], levels)
        runtime_rules.append(dict({key: value for key, value in rule.items() if key != "examples"},
                                  severity=severity.rule_severity(level), cve_severity=level))
    runtime = {"schema_version": 1, "rules": runtime_rules}
    data_rules.load_runtime(runtime)
    (ROOT / "src" / "paladin" / "resources" / "change-rules.json").write_text(
        json.dumps(runtime, indent=1, sort_keys=True) + "\n", encoding="ascii", newline="\n")
    noisy = sorted(((v["files"], k) for k, v in hits.items() if v["files"]), reverse=True)[:15]
    print(json.dumps({k: v for k, v in record.items() if k not in ("rules", "first_heldout_scan")}, indent=1))
    print("corpus files:", files, "noisiest rules (files hit):", noisy)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
