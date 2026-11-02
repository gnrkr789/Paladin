"""Fixed development retrieval evaluation. Requires a prepared model and index.

Usage: python -B eval/run_m2.py [FIXTURE] [OUTPUT] [--force] (defaults: the v1 query set and its
evidence file). An existing result for a held-out fixture is never replaced without --force.
"""
import hashlib
import json
from pathlib import Path
import statistics
import sys
import time
from unittest.mock import patch

from paladin.embedding import LocalEmbedder
from paladin.knowledge import search_patterns
from paladin.language import require_english


def check_output(data, output, force):
    """A held-out set is measured once: refuse to replace its recorded result unless forced."""
    if "held_out" in data.get("purpose", "") and output.exists() and not force:
        raise SystemExit("refusing to overwrite held-out evidence {}; pass --force or another output".format(output))


def main(argv=None):
    root = Path(__file__).resolve().parents[1]
    args = sys.argv[1:] if argv is None else argv
    force = "--force" in args
    args = [arg for arg in args if arg != "--force"]
    fixture = root / (args[0] if args else "eval/m2-queries.json")
    data = json.loads(fixture.read_text(encoding="utf-8"))
    output = root / (args[1] if len(args) > 1 else "docs/evidence/m2/retrieval-evaluation.json")
    check_output(data, output, force)
    for item in data["queries"]:
        if item["language"] != "en":
            raise ValueError("evaluation supports English only")
        require_english(item["query"])
    started = time.perf_counter()
    encoder = LocalEmbedder(root)
    load_seconds = time.perf_counter() - started
    results = []
    with patch("urllib.request.urlopen", side_effect=AssertionError("unexpected model download during evaluation")):
        for item in data["queries"]:
            started = time.perf_counter()
            result = search_patterns(root, item["query"], limit=5, embedder=encoder)
            elapsed = time.perf_counter() - started
            if result["status"] != "complete":
                raise RuntimeError(json.dumps(result))
            ids = [x["pattern"]["pattern_id"] for x in result["matches"]]
            relevant = set(item["relevant"])
            rank = next((i + 1 for i, key in enumerate(ids) if key in relevant), None)
            results.append({"id": item["id"], "language": item["language"], "query": item["query"],
                            "expected": item["relevant"], "returned": ids, "first_relevant_rank": rank,
                            "hit_at_5": rank is not None, "recall_at_5": len(set(ids) & relevant) / len(relevant),
                            "reciprocal_rank": 1 / rank if rank else 0, "seconds": elapsed})
            print(item["id"], rank, ids[0], round(elapsed, 3), flush=True)
    total = len(results)
    summary = {"query_fixture_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(), "queries": total,
               "manifest": result["manifest"], "model_load_seconds": load_seconds,
               "hit_at_5": sum(x["hit_at_5"] for x in results) / total,
               "recall_at_5": statistics.mean(x["recall_at_5"] for x in results),
               "mrr": statistics.mean(x["reciprocal_rank"] for x in results),
               "p50_seconds": statistics.median(x["seconds"] for x in results),
               "p95_seconds": sorted(x["seconds"] for x in results)[int(total * .95) - 1],
               "languages": {lang: sum(x["hit_at_5"] for x in results if x["language"] == lang)
                             / sum(x["language"] == lang for x in results) for lang in ["en"]},
               "gate": data["gate"], "ranking": result.get("ranking", "dense_v1"),
               "security_prevention_evaluated": False}
    summary["gate_pass"] = summary["hit_at_5"] >= data["gate"]["hit_at_5"] and summary["mrr"] >= data["gate"]["mrr"]
    output.write_text(json.dumps({"summary": summary, "results": results}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0 if summary["gate_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
