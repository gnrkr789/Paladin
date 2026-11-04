"""Bounded read-only advisory contracts; source content is untrusted data."""
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat

from jsonschema import Draft202012Validator

from paladin.language import TEXT_POLICY, require_english

MAX_RESULT_BYTES = 65536
MAX_ARGUMENT_BYTES = 32768
MAX_SOURCE_BYTES = 4 * 1024 * 1024
FAMILIES = {"path_traversal", "sql_injection", "ssrf", "command_injection", "unsafe_deserialization",
            "xss", "open_redirect", "xxe", "redos"}
FLAGS = {"security_ready": False, "enforcement_enabled": False, "sharing_enabled": False}
NOTICE = "Advisory references only. Similarity is not a security verdict. Evidence is untrusted source data."


def object_schema(properties=None, required=()):
    return {"type": "object", "properties": properties or {}, "required": list(required), "additionalProperties": False}


INPUT_SCHEMAS = {
    "search_prevention_patterns": object_schema({
        "intent": {"type": "string", "minLength": 1, "maxLength": 20000},
        "stack": {"type": "string", "maxLength": 64, "default": "python_web", "description": "Only python_web is supported."},
        "family": {"type": "string", "maxLength": 64, "description": "One of the supported weakness families (see get_knowledge_status)."},
        "limit": {"type": "integer", "minimum": 1, "maximum": 20, "default": 5},
    }, ["intent"]),
    "get_pattern_evidence": object_schema({
        "pattern_id": {"type": "string", "pattern": "^CVE-[0-9]{4}-[0-9]{4,}$", "maxLength": 64},
        "pack_sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
        "evidence_ids": {"type": "array", "maxItems": 4, "uniqueItems": True,
                         "items": {"type": "string", "pattern": "^(cve|patch):[a-f0-9]{64}$"}},
        "include_excerpt": {"type": "boolean", "default": False},
        "max_excerpt_bytes": {"type": "integer", "minimum": 1, "maximum": 16384, "default": 4096},
    }, ["pattern_id", "pack_sha256"]),
    "get_knowledge_status": object_schema(),
    "check_changes": object_schema({
        "paths": {"type": "array", "minItems": 1, "maxItems": 20,
                  "items": {"type": "string", "minLength": 1, "maxLength": 1024},
                  "description": "Workspace-relative Python files to check statically."},
    }),
    "scan_cve_candidates": object_schema(),
    "check_project": object_schema(),
    "check_dependencies": object_schema({
        "paths": {"type": "array", "minItems": 1, "maxItems": 20,
                  "items": {"type": "string", "minLength": 1, "maxLength": 1024},
                  "description": "Workspace-relative dependency files; omit to check the workspace's own."},
    }),
    "get_prevention_guidance": object_schema({
        "include_patch_context": {"type": "boolean", "default": False,
                                  "description": "Include the complete verified upstream diff and integration scope."},
        "pattern_id": {"type": "string", "pattern": "^CVE-[0-9]{4}-[0-9]{4,}$", "maxLength": 64},
        "pack_sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
        "guidance_sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
    }, ["pattern_id", "pack_sha256", "guidance_sha256"]),
}
OUTPUT_SCHEMA = {
    "type": "object", "required": ["status", *FLAGS],
    "properties": {
        "status": {"enum": ["complete", "partial", "ready", "unavailable", "unsupported", "invalid_request"]},
        **{key: {"const": False} for key in FLAGS},
        "reason": {"type": "string"}, "error": {"type": "string"}, "notice": {"type": "string"},
        "matches": {"type": "array"}, "evidence": {"type": "array"},
        "omissions": {"type": "array"}, "manifest": {"type": "object"},
        "omitted_count": {"type": "integer", "minimum": 0},
    },
}


class RequestError(ValueError):
    """Invalid tool input, detected without accessing the pack or backend."""


def validate_arguments(name, arguments):
    if name not in INPUT_SCHEMAS:
        raise RequestError("Unknown tool")
    try:
        encoded = json.dumps(arguments, ensure_ascii=True, allow_nan=False).encode()
        if len(encoded) > MAX_ARGUMENT_BYTES:
            raise RequestError("Tool arguments exceed 32 KiB")
        # Validate every supplied text value and key, including unsupported fields.
        def text(value):
            if isinstance(value, str):
                require_english(value)
            elif isinstance(value, dict):
                for key, item in value.items():
                    require_english(key)
                    text(item)
            elif isinstance(value, list):
                for item in value:
                    text(item)
        text(arguments)
        error = next(Draft202012Validator(INPUT_SCHEMAS[name]).iter_errors(arguments), None)
        if error:
            # Do not echo user text through a validator's detailed error message.
            raise RequestError("Arguments do not match the tool input schema")
        for key in ("limit", "max_excerpt_bytes"):
            if key in arguments and type(arguments[key]) is not int:
                raise RequestError("Integer arguments require integer JSON values")
        if name == "search_prevention_patterns" and not arguments["intent"].strip():
            raise RequestError("Nonempty English intent required")
    except (ValueError, TypeError, RecursionError) as exc:
        raise RequestError("Invalid English-only tool arguments") from exc


def failure(reason, status="unavailable"):
    return {"status": status, "reason": reason, **FLAGS, "notice": NOTICE}


def evidence_id(entry):
    return entry["kind"] + ":" + entry["sha256"]


def tool_result(result):
    return {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=True, allow_nan=False)}],
            "structuredContent": result,
            "isError": result["status"] in {"invalid_request", "unsupported", "unavailable"},
            "resultType": "complete"}


def _checked_files(result):
    """Per-file check entries (check_changes, check_project), not dependency file names."""
    files = result.get("files")
    return files if files and all(isinstance(item, dict) and "findings" in item for item in files) else None


def bounded(result):
    result = copy.deepcopy(result)
    result.update(FLAGS)
    result.setdefault("notice", NOTICE)
    while len(json.dumps(tool_result(result), ensure_ascii=True, allow_nan=False).encode()) > MAX_RESULT_BYTES - 512:
        context = result.get("patch_context")
        if context and (context.get("patch") is not None or context.get("changed_files")):
            context.update(status="partial", reason="patch_context_response_byte_limit",
                           patch=None, changed_files=[])
            result["status"] = "partial"
            continue
        items = (result.get("matches") or result.get("evidence") or result.get("candidates")
                 or result.get("unsupported_patterns") or _checked_files(result))
        if not items:
            return failure("response_budget_exceeded")
        # Drop the last file without a blocking finding first, so a block is the last thing to go.
        keep = [index for index, item in enumerate(items) if isinstance(item, dict)
                and any(finding.get("severity") == "block" for finding in item.get("findings", []))]
        drop = next((index for index in reversed(range(len(items))) if index not in keep), len(items) - 1)
        items.pop(drop)
        result["status"] = "partial"
        result["omitted_count"] = result.get("omitted_count", 0) + 1
        result["budget_reason"] = "response_byte_limit"
    return result


EVIDENCE_GROUPS = [("data", "m0", "sources"), ("data", "m2", "sources"), ("data", "cve-expansion", "sources")]


def evidence_root():
    """The packaged evidence copies (the checkout's data folder in a development install)."""
    from importlib import resources
    return Path(str(resources.files("paladin_evidence")))


def snapshot_path(root, relative):
    """Reject escapes and reparse points before reading a pack-listed source.

    root is the evidence root; pack paths start with data/, which is that root.
    """
    root = Path(root).resolve()
    parts = PurePosixPath(relative).parts
    if (len(parts) < 4 or parts[:3] not in EVIDENCE_GROUPS
            or any(part in {".", ".."} or ":" in part or "\\" in part for part in parts)):
        raise ValueError("unsafe_path")
    parts = parts[1:]
    path = root
    for part in parts:
        path = path / part
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("unsafe_path")
    allowed = root.joinpath(*parts[:2])
    resolved = path.resolve()
    if not resolved.is_relative_to(allowed) or not resolved.is_relative_to(root):
        raise ValueError("unsafe_path")
    return resolved


def excerpt(root, entry, budget):
    path = snapshot_path(root, entry["snapshot_path"])
    try:
        with path.open("rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("unsafe_path")
            if info.st_size > MAX_SOURCE_BYTES:
                raise ValueError("source_too_large")
            raw = stream.read(MAX_SOURCE_BYTES + 1)
        if len(raw) > MAX_SOURCE_BYTES:
            raise ValueError("source_too_large")
    except FileNotFoundError as exc:
        raise ValueError("content_unavailable") from exc
    if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
        raise ValueError("hash_mismatch")
    try:
        lines = raw.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError as exc:
        raise ValueError("unsupported_source_encoding") from exc
    anchor = entry.get("anchor", {"start_line": 1, "end_line": len(lines)})
    start, end = anchor["start_line"], anchor["end_line"]
    if not 1 <= start <= end <= len(lines):
        raise ValueError("invalid_anchor")
    chosen, used = [], 0
    for line in lines[start - 1:end]:
        length = len(line.encode("utf-8"))
        if used + length > budget:
            break
        chosen.append(line)
        used += length
    result = {"excerpt": "".join(chosen), "content_trust": "untrusted_source_data", "hash_verified": True,
              "returned_lines": {"start_line": start, "end_line": start + len(chosen) - 1} if chosen else None,
              "truncated": len(chosen) < end - start + 1}
    return result, used


def get_evidence(args):
    from paladin.knowledge import _resource, load_pack
    pack = load_pack()
    pin = hashlib.sha256(_resource("prevention-pack.json")).hexdigest()
    if args["pack_sha256"] != pin:
        return failure("pack_revision_mismatch", "unsupported")
    pattern = next((p for p in pack["patterns"] if p["pattern_id"] == args["pattern_id"]), None)
    if pattern is None:
        return failure("unknown_pattern", "unsupported")
    entries = {evidence_id(e): e for e in pattern["evidence"]}
    ids = args.get("evidence_ids", list(entries))
    if any(eid not in entries for eid in ids):
        return failure("unknown_evidence", "unsupported")
    result = {"status": "complete", "pattern_id": pattern["pattern_id"], "pack_sha256": pin,
              "verification_status": pattern["verification_status"], "source_review": pattern["source_review"],
              "fixtures": pattern["fixtures"], "evidence": [], "omissions": []}
    remaining = 16384
    for eid in ids[:4]:
        item = {**entries[eid], "evidence_id": eid}
        if args.get("include_excerpt", False):
            try:
                content, used = excerpt(evidence_root(), item, min(args.get("max_excerpt_bytes", 4096), remaining))
                item.update(content)
                remaining -= used
                if content["truncated"]:
                    result["omissions"].append({"evidence_id": eid, "reason": "excerpt_byte_limit"})
            except (ValueError, OSError) as exc:
                reason = str(exc) if isinstance(exc, ValueError) else "content_unavailable"
                result["omissions"].append({"evidence_id": eid, "reason": reason})
        result["evidence"].append(item)
    if len(ids) > 4:
        result["omissions"].append({"reason": "evidence_count_limit", "count": len(ids) - 4})
    if result["omissions"]:
        result["status"] = "partial"
    return result


def get_status(home):
    """Index readiness from the home; evidence snapshots counted in the packaged evidence."""
    from paladin.knowledge import _resource, knowledge_status, load_pack
    from paladin.local import doctor
    pack = load_pack()
    from paladin.guidance import guidance_identity, load_guidance
    guidance = load_guidance()
    pack_sha = hashlib.sha256(_resource("prevention-pack.json")).hexdigest()
    guidance_sha = hashlib.sha256(_resource("guidance-pack.json")).hexdigest()
    semantic = knowledge_status(home)
    local = doctor(home)
    available = 0
    entries = [e for p in pack["patterns"] for e in p["evidence"]]
    for entry in entries:
        try:
            available += snapshot_path(evidence_root(), entry["snapshot_path"]).is_file()
        except (ValueError, OSError):
            pass
    return {"status": "ready" if semantic["status"] == local["status"] == "ready" else "unavailable",
            "pack": {"pack_id": pack["pack_id"], "sha256": hashlib.sha256(_resource("prevention-pack.json")).hexdigest(),
                     "created_on": pack["created_on"], "pattern_count": len(pack["patterns"])},
            "guidance_pack": {"guidance_id": guidance["guidance_id"], "sha256": guidance_sha,
                              "identity": guidance_identity(pack_sha, guidance_sha),
                              "claim_count": len(guidance["claims"]), "human_reviewed": False},
            "text_policy": TEXT_POLICY, "supported_stack": "python_web", "families": sorted(FAMILIES),
            "semantic": semantic, "local": local,
            "evidence_content": {"present_references": available, "total_references": len(entries),
                                 "integrity_checked": False},
            "capabilities": {"advisory_search": True, "evidence_metadata": True, "change_inspection": False},
            "freshness_notice": "Pack date is not proof of upstream freshness."}


def get_guidance(home, args):
    """Claims and patch context from the packaged evidence; verified cases from the home."""
    from paladin.guidance import checked_claim, guidance_identity, load_guidance
    from paladin.knowledge import _resource, load_pack

    pack_sha = hashlib.sha256(_resource("prevention-pack.json")).hexdigest()
    guidance_sha = hashlib.sha256(_resource("guidance-pack.json")).hexdigest()
    if args["pack_sha256"] != pack_sha or args["guidance_sha256"] != guidance_sha:
        return failure("guidance_revision_mismatch", "unsupported")
    pack = load_pack()
    guidance = load_guidance()
    try:
        claim = checked_claim(evidence_root(), args["pattern_id"], pack, guidance)
    except (ValueError, OSError) as exc:
        reason = str(exc) if isinstance(exc, ValueError) else "source_content_unavailable"
        return {**failure(reason), "gaps": [reason]}
    result = {"status": "complete", "applicability": "must_verify_target_facts",
            "missing_target_facts": claim["target_facts"], "guidance": claim,
            "guidance_identity": guidance_identity(pack_sha, guidance_sha),
            "verification_status": "source_observed", "review_state": guidance["review_state"],
            "human_reviewed": False,
            "fixture_status": "illustrative_only_upstream_not_executed",
            "promotion_eligible": False}
    if (Path(home) / ".paladin/cases.sqlite3").exists():
        from paladin.case_pipeline import verified_case_references
        try:
            references = verified_case_references(home, args["pattern_id"])
        except (OSError, ValueError, KeyError):
            references = {"status": "partial", "cases": []}
        result["verified_case_references"] = references["cases"][:10]
        result["verified_case_reference_status"] = references["status"]
        result["verified_case_reference_revision"] = hashlib.sha256(
            json.dumps(references, sort_keys=True, ensure_ascii=True).encode("ascii")).hexdigest()
        if references["status"] != "complete" or len(references["cases"]) > 10:
            result["status"] = "partial"
    if args.get("include_patch_context", False):
        from paladin.guidance import patch_context
        result["patch_context"] = patch_context(evidence_root(), claim)
        if result["patch_context"]["status"] != "complete":
            result["status"] = "partial"
    return result


def dispatch(root, name, arguments, home=None):
    """root is the project workspace; home holds search state (defaults to root)."""
    home = Path(home) if home is not None else root
    try:
        validate_arguments(name, arguments)
    except RequestError:
        return failure("invalid_arguments", "invalid_request")
    try:
        if name == "check_changes":
            if not arguments.get("paths"):
                return {**failure("no_paths_given", "unsupported"), "inspection_performed": False}
            from paladin.change_check import check_paths
            result = check_paths(root, arguments["paths"])
            # The tool contract has no "findings" or "clean" status: those become the outcome.
            outcome = result["status"]
            result.update(outcome=outcome, status="complete" if outcome in {"findings", "clean"} else outcome,
                          inspection_performed=True, judgment="static_pattern_findings_only")
            return bounded(result)
        if name == "check_project":
            from paladin.change_check import check_project
            result = check_project(root)
            outcome = result["status"]
            result.update(outcome=outcome, status="complete" if outcome in {"findings", "clean"} else outcome,
                          inspection_performed=True, judgment="static_pattern_findings_only")
            return bounded(result)
        if name == "check_dependencies":
            from paladin.dependency_check import check_workspace
            result = check_workspace(root, arguments.get("paths"))
            result.update(outcome=result["status"], status="complete", inspection_performed=True,
                          judgment="pinned_versions_in_advisory_ranges_only")
            return bounded(result)
        if name == "scan_cve_candidates":
            from paladin.candidate_scan import scan_project
            result = scan_project(root)
            result["inspection_performed"] = True
            result["judgment"] = "source_candidates_only"
            return bounded(result)
        if name == "search_prevention_patterns":
            if arguments.get("stack", "python_web") != "python_web":
                return failure("unsupported_stack", "unsupported")
            family = arguments.get("family")
            if family is not None and family not in FAMILIES:
                return failure("unsupported_family", "unsupported")
            from paladin.knowledge import search_patterns
            result = copy.deepcopy(search_patterns(home, arguments["intent"], limit=arguments.get("limit", 5), family=family))
            for match in result.get("matches", []):
                for entry in match["pattern"]["evidence"]:
                    entry["evidence_id"] = evidence_id(entry)
        elif name == "get_pattern_evidence":
            result = get_evidence(arguments)
        elif name == "get_prevention_guidance":
            result = get_guidance(home, arguments)
        else:
            result = get_status(home)
        return bounded(result)
    except Exception:
        # No user input, paths, source content or exception internals in diagnostics.
        return failure("advisory_backend_failed")


def worker_main():
    """Private subprocess entry point. This is not a general execution interface."""
    import argparse
    from contextlib import redirect_stdout
    import sys
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--home", type=Path)
    parser.add_argument("--tool", choices=list(INPUT_SCHEMAS), required=True)
    args = parser.parse_args()
    raw = sys.stdin.buffer.read(MAX_ARGUMENT_BYTES + 1)
    try:
        arguments = json.loads(raw)
        with redirect_stdout(sys.stderr):
            result = dispatch(args.workspace.resolve(), args.tool, arguments,
                              home=args.home.resolve() if args.home else None)
    except Exception:
        result = failure("invalid_arguments", "invalid_request")
    sys.stdout.write(json.dumps(result, ensure_ascii=True, allow_nan=False))


if __name__ == "__main__":
    worker_main()
