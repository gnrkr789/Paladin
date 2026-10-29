"""Validate local research data. Never fetch URLs, import snapshots, or run PoCs."""
import argparse
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


FAMILIES = {"path_traversal", "sql_injection", "ssrf", "command_injection", "unsafe_deserialization"}


def validate_dataset(data, *, root, schema_path):
    root = Path(root).resolve()
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = [f"schema:{'/'.join(map(str, e.absolute_path))}:{e.message}" for e in validator.iter_errors(data)]
    if errors:
        return errors

    seen = set()
    evidence_seen = set()
    aligned = []
    source_root = (root / "data/m0/sources").resolve()
    for case in data["cases"]:
        cve = case["cve_id"]
        if cve in seen:
            errors.append(f"duplicate_cve:{cve}")
        seen.add(cve)
        if case["verification_status"] != "candidate":
            if case["patch_alignment"] != "aligned":
                errors.append(f"patch_alignment_required:{cve}")
            if case["record_state"] != "PUBLISHED":
                errors.append(f"published_record_required:{cve}")
            if not case.get("review"):
                errors.append(f"review_record_required:{cve}")
        # M0 has no rule tests or runtime evidence. Source test locations are
        # evidence observations, and cannot establish either of these states.
        if case["rule_enabled"] or case["verification_status"] in {"rule_tested", "reproduced"}:
            errors.append(f"rule_verification_required:{cve}:M0 has no executable rule evidence")

        evidence = {}
        blobs = {}
        for item in case["evidence"]:
            eid = item["evidence_id"]
            if eid in evidence_seen:
                errors.append(f"duplicate_evidence_id:{eid}")
            evidence_seen.add(eid)
            evidence[eid] = item
            path = (root / item["path"]).resolve()
            if not path.is_relative_to(root) or not path.is_relative_to(source_root):
                errors.append(f"evidence_path_outside_root:{eid}")
                continue
            try:
                blob = path.read_bytes()
            except OSError:
                errors.append(f"snapshot_missing:{eid}")
                continue
            blobs[eid] = blob
            if hashlib.sha256(blob).hexdigest() != item["sha256"]:
                errors.append(f"snapshot_hash_mismatch:{eid}")
            if item["kind"] == "cve":
                try:
                    record = json.loads(blob)
                    metadata = record["cveMetadata"]
                    if metadata["cveId"] != cve or metadata["state"] != case["record_state"]:
                        errors.append(f"cve_record_mismatch:{eid}")
                except (ValueError, KeyError, TypeError):
                    errors.append(f"cve_record_invalid:{eid}")

        if not any(e["kind"] == "cve" for e in evidence.values()):
            errors.append(f"cve_evidence_missing:{cve}")
        anchor = case["patch_anchor"]
        patch = evidence.get(anchor["evidence_id"])
        if patch is None or patch["kind"] != "patch":
            errors.append(f"patch_evidence_missing:{cve}")
        elif anchor["evidence_id"] in blobs:
            lines = blobs[anchor["evidence_id"]].decode("utf-8").splitlines()
            if not (1 <= anchor["start_line"] <= anchor["end_line"] <= len(lines)):
                errors.append(f"patch_anchor_out_of_range:{cve}")

        has_poc = bool(case["poc_candidates"])
        if has_poc != (case["poc_status"] == "index_candidate_found"):
            errors.append(f"poc_status_mismatch:{cve}")
        has_tests = bool(case["upstream_tests"]["locations"])
        if has_tests != (case["upstream_tests"]["status"] == "source_observed_not_run"):
            errors.append(f"upstream_test_status_mismatch:{cve}")
        if case["patch_alignment"] == "aligned" and case["record_state"] == "PUBLISHED":
            aligned.append(case)

    if len({c["cve_id"] for c in aligned}) < 5:
        errors.append("m0_aligned_count:at least five independent aligned candidates required")
    if {c["family"] for c in aligned} != FAMILIES:
        errors.append("m0_family_coverage:all five planned families required")
    return errors


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=root / "data/m0/cases.json")
    args = parser.parse_args()
    try:
        data = json.loads(args.dataset.read_text(encoding="utf-8"))
        errors = validate_dataset(data, root=root, schema_path=root / "schemas/m0-corpus.schema.json")
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}")
        return 1
    if errors:
        for error in errors:
            print(error)
        return 1
    cases = data["cases"]
    print(json.dumps({"status": "PASS", "cases": len(cases),
                      "aligned_candidates": sum(c["patch_alignment"] == "aligned" for c in cases),
                      "quarantined": sum(c["patch_alignment"] != "aligned" for c in cases),
                      "active_rules": sum(c["rule_enabled"] for c in cases),
                      "sharing_enabled": any(c["contribution"]["sharing_enabled"] for c in cases)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
