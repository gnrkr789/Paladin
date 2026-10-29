"""Pinned candidate corrections; no target inspection or approval is implied."""
import hashlib
import json
import re

from jsonschema import Draft202012Validator

from paladin.knowledge import _resource, load_pack
from paladin.language import TEXT_POLICY, validate_authored_text

PILOT_IDS = {
    "CVE-2021-31542", "CVE-2022-34265", "CVE-2024-11168",
    "CVE-2022-24065", "CVE-2024-2912",
}


def repair_constraints(pattern_id):
    """Compatibility obligations derived from the pinned upstream repair."""
    return {
        "CVE-2022-24065": [
            "Preserve literal Mercurial revisions with a leading hyphen using the supported -- terminator; do not add blanket prefix rejection.",
            "Scope the terminator to Mercurial. Preserve Git checkout argument semantics and existing error translation.",
            "Validate containment and successful literal checkout separately; rejecting every unusual value is not a complete compatibility repair.",
        ],
        "CVE-2022-34265": [
            "Preserve the upstream structural identifier grammar, including underscores, hyphens and parentheses; a date-part allowlist may break backend extensions.",
            "Apply full-string validation before compilation for both Extract and Trunc, and preserve backend override capability and bound data values.",
        ],
    }.get(pattern_id, [
        "Compare the accepted-input domain before and after the patch; avoid additional rejection beyond the source-supported correction.",
    ])


def patch_context(root, claim, max_bytes=24000):
    """Return source data for all integration hunks, without target approval."""
    from paladin.advisory import MAX_SOURCE_BYTES, snapshot_path

    evidence = claim["provenance"]["patch"]
    path = snapshot_path(root, evidence["snapshot_path"])
    with path.open("rb") as stream:
        raw = stream.read(MAX_SOURCE_BYTES + 1)
    if len(raw) > MAX_SOURCE_BYTES or hashlib.sha256(raw).hexdigest() != evidence["sha256"]:
        raise ValueError("source_content_changed")
    constraints = repair_constraints(claim["pattern_id"])
    base = {"format_version": "patch-context-v2", "sha256": evidence["sha256"],
            "repair_constraints": constraints, "constraints_basis": "upstream_patch_scope_inference",
            "format": "upstream_diff_untrusted_data", "target_inspected": False,
            "requirements": [
                "Map every upstream changed path to the target layout before editing.",
                "Inspect constructor, caller and deployment wiring together with the guarded function.",
                "If required wiring is outside the editable scope, report the scope gap before claiming completion.",
                "Run risk and safe regression cases through the real entrypoint, including internal routes.",
                "Check upstream regression tests and supported behavior beyond the example inputs.",
            ]}
    base["identity"] = hashlib.sha256(json.dumps(base, sort_keys=True).encode("ascii")).hexdigest()
    text = raw.decode("utf-8")
    # Reserve space for the surrounding claim and the MCP text envelope.
    wire_size = len(json.dumps(json.dumps(text, ensure_ascii=True), ensure_ascii=True).encode("ascii"))
    if len(raw) > max_bytes or wire_size > max_bytes:
        return {**base, "status": "partial", "reason": "patch_context_byte_limit",
                "patch_bytes": len(raw), "changed_files": [], "patch": None}
    headers = re.findall(r"^diff --git a/(\S+) b/(\S+)$", text, re.MULTILINE)
    header_count = sum(line.startswith("diff --git ") for line in text.splitlines())
    if not headers or len(headers) != header_count or not valid_patch_hunks(text):
        return {**base, "status": "partial", "reason": "unsupported_patch_paths",
                "changed_files": [], "patch": None}
    # Preserve both sides of renames and deletions; paths are references only.
    files = list(dict.fromkeys(path for pair in headers for path in pair))
    return {**base, "status": "complete", "changed_files": files, "patch": text}


def valid_patch_hunks(text):
    """Conservatively accept text diffs only when every hunk count is complete."""
    sections = re.split(r"^diff --git ", text, flags=re.MULTILINE)[1:]
    for section in sections:
        lines = section.splitlines()
        hunks = [index for index, line in enumerate(lines) if line.startswith("@@")]
        if not hunks:
            return False
        for index in hunks:
            match = re.match(r"^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@", lines[index])
            if not match:
                return False
            old, new = (int(value) if value is not None else 1 for value in match.groups())
            for line in lines[index + 1:]:
                if old == new == 0:
                    if not line.strip():
                        continue
                    if (line.startswith("@@") or line == "-- "
                            or re.match(r"^From [a-f0-9]{40} Mon Sep 17 ", line)):
                        break
                    if line.startswith("\\ No newline"):
                        continue
                    if line and line[0] in " +-":
                        return False
                    continue
                if line.startswith("\\ No newline"):
                    continue
                if not line or line[0] not in " +-":
                    return False
                old -= line[0] in " -"
                new -= line[0] in " +"
                if old < 0 or new < 0:
                    return False
            if old or new:
                return False
    return bool(sections)


def load_guidance():
    raw = _resource("guidance-pack.json")
    lock = json.loads(_resource("guidance-pack.lock.json"))
    if hashlib.sha256(raw).hexdigest() != lock["sha256"]:
        raise ValueError("guidance_hash_mismatch")
    guidance = json.loads(raw)
    validate_authored_text(guidance)
    schema = json.loads(_resource("guidance-pack.schema.json"))
    if not Draft202012Validator(schema).is_valid(guidance):
        raise ValueError("invalid_guidance_schema")
    ids = [claim["pattern_id"] for claim in guidance["claims"]]
    if (set(ids) != PILOT_IDS or len(ids) != len(set(ids))
            or guidance["guidance_id"] != lock["guidance_id"]
            or len(ids) != lock["claim_count"] or guidance["text_policy"] != TEXT_POLICY):
        raise ValueError("invalid_guidance_manifest")
    return guidance


def guidance_identity(pack_sha, guidance_sha):
    return hashlib.sha256((pack_sha + ":" + guidance_sha).encode("ascii")).hexdigest()


def checked_claim(root, pattern_id, pack, guidance):
    from paladin.advisory import MAX_SOURCE_BYTES, snapshot_path

    pattern = next((p for p in pack["patterns"] if p["pattern_id"] == pattern_id), None)
    claim = next((c for c in guidance["claims"] if c["pattern_id"] == pattern_id), None)
    if pattern is None or claim is None:
        raise ValueError("unknown_guidance_pattern")
    if (pattern["patch_alignment"] != "aligned" or pattern["record_state"] != "PUBLISHED"
            or pattern["verification_status"] != "source_observed"):
        raise ValueError("source_claim_not_aligned")
    evidence = {}
    line_counts = {}
    for item in pattern["evidence"]:
        path = snapshot_path(root, item["snapshot_path"])
        with path.open("rb") as stream:
            raw = stream.read(MAX_SOURCE_BYTES + 1)
        if len(raw) > MAX_SOURCE_BYTES or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError("source_content_changed")
        evidence[item["kind"]] = item
        line_counts[item["kind"]] = len(raw.splitlines())
    if set(evidence) != {"cve", "patch"}:
        raise ValueError("incomplete_source_pair")
    lines = claim["patch_lines"]
    anchor = evidence["patch"]["anchor"]
    if not (anchor["start_line"] <= lines["start_line"] <= lines["end_line"] <= anchor["end_line"]):
        raise ValueError("guidance_anchor_outside_evidence")
    for field, supports in claim["support"].items():
        if field != "cause" and len(supports) != len(claim[field]):
            raise ValueError("guidance_support_count_mismatch")
        groups = [supports] if field == "cause" else supports
        for group in groups:
            for reference in group:
                kind, _, span = reference.partition(":")
                if kind in {"process", "inference"}:
                    if reference not in {"process:target_not_inspected", "process:source_audit",
                                         "inference:patch_scope"}:
                        raise ValueError("unknown_guidance_basis")
                    continue
                start, end = map(int, span.split("-"))
                if not 1 <= start <= end <= line_counts[kind]:
                    raise ValueError("guidance_support_outside_source")
                if kind == "patch" and not (lines["start_line"] <= start <= end <= lines["end_line"]):
                    raise ValueError("guidance_support_outside_anchor")
    return {**claim, "cause": pattern["cause"], "provenance": {
        "cve": {"sha256": evidence["cve"]["sha256"], "snapshot_path": evidence["cve"]["snapshot_path"]},
        "patch": {"sha256": evidence["patch"]["sha256"],
                  "snapshot_path": evidence["patch"]["snapshot_path"], "lines": lines},
    }}
