"""Orchestrate narrowly scoped local verification and case promotion."""
import hashlib
import json
from pathlib import Path
import re
import stat

from paladin.candidate_scan import scan_project
from paladin.case_store import _validate as validate_record, list_cases, promote_case
from paladin.case_verification import (RULE_ID, VERIFIER_ID,
                                       _repair_bytes, _source, derive_checks,
                                       propose_repair, verify_case)
from paladin.language import require_english
from paladin.case_auth import sign_evidence, verify_evidence
from paladin.case_runtime import load_runtime


def _safe_directory(path):
    path = Path(path)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("linked_case_path")
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("case_path_not_directory")
    else:
        path.mkdir()
    return path


def _paths(workspace):
    workspace = Path(workspace).absolute()
    require_english(str(workspace))
    if not workspace.is_dir() or workspace.is_symlink():
        raise ValueError("invalid_workspace")
    state = _safe_directory(workspace / ".paladin")
    db = state / "cases.sqlite3"
    if db.exists() or db.is_symlink():
        info = db.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("linked_case_database")
    return state, db


def _store_blob(directory, name, data):
    path = directory / name
    try:
        with path.open("xb") as stream:
            stream.write(data)
    except FileExistsError:
        info = path.lstat()
        if (stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
                or path.read_bytes() != data):
            raise ValueError("evidence_conflict")


def run_case(workspace, project, candidate_id):
    """Repair a separate source snapshot, verify it, then persist only passing cases.

    Project bytes execute only inside the configured isolated observer runtime.
    """
    require_english(candidate_id)
    if not re.fullmatch(r"[0-9a-f]{64}", candidate_id):
        raise ValueError("invalid_candidate_id")
    scan = scan_project(project)
    candidates = [item for item in scan["candidates"] if item["candidate_id"] == candidate_id]
    if len(candidates) != 1:
        raise ValueError("candidate_missing_or_changed")
    candidate = candidates[0]
    runtime = load_runtime(workspace)
    state, db = _paths(workspace)
    identity = hashlib.sha256((str(Path(project).resolve()) + "|" + candidate["path"]).encode("ascii")).hexdigest()
    valid = verified_case_references(workspace, candidate["cve_id"])
    valid_ids = {item["case_id"] for item in valid["cases"]}
    for case in list_cases(db):
        if (case["case_id"] in valid_ids and case["candidate_id"] == candidate_id
                and case["project_identity"] == identity):
            return {"status": "promoted", "candidate": candidate, "case": case,
                    "scan_status": scan["status"], "reused": True,
                    "notice": "Reused authenticated isolated observation; no human review."}
    stages = _safe_directory(state / "case-staging")
    stage = _safe_directory(stages / candidate_id)
    parts = candidate["path"].split("/")
    destination = stage
    for component in parts[:-1]:
        destination = _safe_directory(destination / component)
    destination = destination / parts[-1]
    _, original = _source(project, candidate["path"])
    if not destination.exists():
        with destination.open("xb") as stream:
            stream.write(original)
        propose_repair(project, stage, candidate)
    result = verify_case(project, stage, candidate, runtime=runtime)
    evidence = sign_evidence(workspace, result["evidence"])
    raw = json.dumps(evidence, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    digest = hashlib.sha256(raw).hexdigest()
    result["record"]["evidence_sha256"] = digest
    evidence_dir = _safe_directory(state / "case-evidence")
    for root, key in ((project, "before_sha256"), (stage, "after_sha256")):
        _, source = _source(root, candidate["path"])
        if hashlib.sha256(source).hexdigest() != result["record"][key]:
            raise ValueError("evidence_source_changed")
        _store_blob(evidence_dir, "source-" + result["record"][key] + ".py", source)
    _store_blob(evidence_dir, digest + ".json", raw)
    if result["status"] != "verified":
        return {"status": "not_verified", "candidate": candidate, "checks": evidence["checks"],
                "evidence_sha256": digest, "scan_status": scan["status"]}
    case = promote_case(db, result["record"])
    return {"status": "promoted", "candidate": candidate, "case": case,
            "checks": evidence["checks"], "scan_status": scan["status"],
            "staged_source": str(destination), "evidence_sha256": digest,
            "notice": "Isolated argument and checkout observations only; no human review or security verdict."}


def verified_case_references(workspace, cve_id):
    """Return only stored references whose evidence and case hashes still match."""
    require_english(str(workspace))
    require_english(cve_id)
    workspace = Path(workspace).absolute()
    state = workspace / ".paladin"
    db = state / "cases.sqlite3"
    if not db.exists():
        return {"status": "complete", "cases": []}
    state, db = _paths(workspace)
    evidence_dir = state / "case-evidence"
    if not evidence_dir.is_dir():
        return {"status": "partial", "cases": []}
    directory_info = evidence_dir.lstat()
    if stat.S_ISLNK(directory_info.st_mode) or getattr(directory_info, "st_file_attributes", 0) & 0x400:
        return {"status": "partial", "cases": []}
    matches, damaged = [], False
    for case in list_cases(db):
        if case.get("cve_id") != cve_id:
            continue
        evidence_sha = case.get("evidence_sha256", "")
        if not re.fullmatch(r"[0-9a-f]{64}", evidence_sha):
            damaged = True
            continue
        path = evidence_dir / (evidence_sha + ".json")
        try:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("linked_evidence")
            if info.st_size > 16000000:
                raise ValueError("evidence_too_large")
            with path.open("rb") as stream:
                raw = stream.read(16000001)
            if len(raw) > 16000000:
                raise ValueError("evidence_too_large")
            content = {key: value for key, value in case.items() if key != "case_id"}
            validate_record(content)
            actual_case_id = hashlib.sha256(json.dumps(content, sort_keys=True, separators=(",", ":"),
                                                        ensure_ascii=True).encode("ascii")).hexdigest()
            if hashlib.sha256(raw).hexdigest() != evidence_sha or actual_case_id != case["case_id"]:
                raise ValueError("case_identity_mismatch")
            evidence = json.loads(raw)
            if not isinstance(evidence, dict):
                raise ValueError("invalid_evidence")
            if not verify_evidence(workspace, evidence):
                raise ValueError("unauthenticated_evidence")
            if evidence.get("runtime") != load_runtime(workspace):
                raise ValueError("runtime_policy_changed")
            before_hash = case["before_sha256"]
            after_hash = case["after_sha256"]
            if (evidence.get("before_sha256") != case["before_sha256"]
                    or evidence.get("after_sha256") != case["after_sha256"]
                    or evidence.get("verifier_id") != VERIFIER_ID or case["verifier_id"] != VERIFIER_ID
                    or (case["rule_id"], case["cve_id"]) not in {
                        (RULE_ID, "CVE-2022-24065"),
                        ("CVE-2023-5752:mercurial-revision-v1", "CVE-2023-5752")}
                    or evidence.get("candidate", {}).get("candidate_id") != case["candidate_id"]
                    or any(evidence.get("checks", {}).get(key) is not True or case.get(key) is not True for key in (
                        "before_risk_observed", "after_risk_blocked",
                        "safe_before_passed", "safe_after_passed"))
                    or case["human_reviewed"] is not False):
                raise ValueError("case_evidence_disagrees")
            candidate = evidence["candidate"]
            path_text = require_english(candidate["path"])
            line = candidate["line"]
            if type(line) is not int or line < 1:
                raise ValueError("invalid_candidate_line")
            expected_candidate = hashlib.sha256("\0".join(
                (case["rule_id"], path_text, str(line), before_hash)).encode("ascii")).hexdigest()
            if (candidate.get("source_sha256") != before_hash or candidate.get("rule_id") != case["rule_id"]
                    or candidate.get("cve_id") != case["cve_id"] or expected_candidate != case["candidate_id"]):
                raise ValueError("candidate_evidence_disagrees")
            adapter = "cookiecutter" if case["rule_id"] == RULE_ID else "pip-mercurial"
            if evidence.get("adapter") != adapter or derive_checks(evidence["before"], evidence["after"], adapter) != evidence["checks"]:
                raise ValueError("case_observations_disagree")
            sources = []
            for source_hash in (before_hash, after_hash):
                source_path = evidence_dir / ("source-" + source_hash + ".py")
                source_info = source_path.lstat()
                if stat.S_ISLNK(source_info.st_mode) or getattr(source_info, "st_file_attributes", 0) & 0x400:
                    raise ValueError("linked_source_evidence")
                if source_info.st_size > 1000000:
                    raise ValueError("source_evidence_too_large")
                with source_path.open("rb") as stream:
                    source = stream.read(1000001)
                if hashlib.sha256(source).hexdigest() != source_hash:
                    raise ValueError("source_evidence_mismatch")
                sources.append(source)
            if _repair_bytes(sources[0], case["rule_id"]) != sources[1]:
                raise ValueError("unsupported_repair_evidence")
            matches.append({"case_id": case["case_id"], "cve_id": case["cve_id"],
                            "rule_id": case["rule_id"], "before_sha256": case["before_sha256"],
                            "after_sha256": case["after_sha256"], "evidence_sha256": evidence_sha,
                            "human_reviewed": case["human_reviewed"]})
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            damaged = True
    return {"status": "partial" if damaged else "complete", "cases": matches}
