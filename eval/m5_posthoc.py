"""Post hoc sensitivity analysis for partial, excerpt-limited MCP evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

from eval.m5_harness import score_attempt, summarize


def evidence_use(events: list[dict], expected_pack: str | None = None) -> dict:
    """Count metadata use when only requested excerpts hit the byte limit."""
    evidence = []
    messages = []
    first_edit = None
    for index, event in enumerate(events):
        if event.get("type") != "item.completed":
            continue
        item = event.get("item") or {}
        if item.get("type") == "file_change" and first_edit is None:
            first_edit = index
        elif item.get("type") == "agent_message":
            messages.append((index, item.get("text") or ""))
        elif item.get("type") == "mcp_tool_call" and item.get("server") == "paladin":
            if item.get("tool") != "get_pattern_evidence" or item.get("status") != "completed":
                continue
            result = (item.get("result") or {}).get("structured_content") or {}
            if result.get("status") not in ("complete", "partial"):
                continue
            if expected_pack is not None and result.get("pack_sha256") != expected_pack:
                continue
            if not result.get("pattern_id") or not result.get("evidence"):
                continue
            omissions = result.get("omissions") or []
            if any(item.get("reason") != "excerpt_byte_limit" for item in omissions):
                continue
            evidence.append((index, result["pattern_id"], result["status"]))
    consumed = any(
        evidence_index < message_index < (first_edit if first_edit is not None else len(events))
        and pattern_id in message
        for evidence_index, pattern_id, _ in evidence
        for message_index, message in messages
    )
    return {"consumed": consumed, "eligible_evidence": [
        {"pattern_id": pattern_id, "status": status}
        for _, pattern_id, status in evidence
    ]}


def analyze(root: Path) -> dict:
    """Preserve the preregistered score and write a separate sensitivity result."""
    root = Path(root)
    protocol_path = root / "eval/m5/protocol.json"
    protocol = json.loads(protocol_path.read_text(encoding="ascii"))
    pack = root / "src/paladin/resources/prevention-pack.json"
    pack_sha = hashlib.sha256(pack.read_bytes()).hexdigest()
    evidence_dir = root / "docs/evidence/m5"
    rows = []
    revised = []
    missing = []
    for index, scheduled in enumerate(protocol["schedule"]):
        name = f"{index:03d}-{scheduled['case_id']}-{scheduled['arm']}"
        folder = evidence_dir / "runs" / name
        result_path = folder / "run.json"
        if not result_path.is_file():
            missing.append(name)
            continue
        run = json.loads(result_path.read_text(encoding="ascii"))
        score = run["score"]
        if run["arm"] == "C":
            events = [json.loads(line) for line in (folder / "host.jsonl").read_text(
                encoding="utf-8").splitlines()]
            use = evidence_use(events, pack_sha)
            oracle = run["oracle"]
            adjusted = score_attempt(
                kind=run["kind"], arm="C", host_exit=run["host"]["exit_code"],
                before_sha=run["before_sha256"], after_sha=run["after_sha256"],
                functionality=oracle["functional"] if oracle else None,
                vulnerability=oracle["vulnerable"] if oracle else None,
                called=run["trace"]["called"], consumed=use["consumed"],
            )
            if adjusted != score:
                revised.append({"run": name, "original": score,
                                "sensitivity": adjusted, "evidence": use})
            score = adjusted
        rows.append({"arm": run["arm"], "kind": run["kind"], **score})
    result = {"kind": "post_hoc_sensitivity_not_primary",
              "reason": "Frozen scorer excluded partial evidence responses with excerpt_byte_limit.",
              "recorded": len(rows), "scheduled": len(protocol["schedule"]),
              "missing": missing, "revised_C_runs": revised,
              "summary": summarize(rows)}
    output = evidence_dir / (
        "posthoc-summary.json" if not missing else f"posthoc.partial-{len(rows)}.json")
    if output.exists():
        raise FileExistsError("Post hoc output exists; preserve it")
    with output.open("x", encoding="ascii", newline="\n") as stream:
        json.dump(result, stream, indent=2, ensure_ascii=True)
        stream.write("\n")
    return result


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python -m eval.m5_posthoc PROJECT_ROOT")
    outcome = analyze(Path(sys.argv[1]))
    print(json.dumps({"recorded": outcome["recorded"],
                      "revised_C_runs": len(outcome["revised_C_runs"]),
                      "missing": len(outcome["missing"])}))
