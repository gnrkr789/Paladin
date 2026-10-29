"""Internal storage for verifier-produced case records.

Validation checks record structure, not the truth of caller-supplied claims.
Only the verifier pipeline should construct records. Stored observations are not
security verdicts or evidence of human approval.
"""

import hashlib
import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path

from .language import require_english

_TEXT_FIELDS = ("candidate_id", "cve_id", "rule_id", "project_identity", "verifier_id")
_HASH_FIELDS = ("before_sha256", "after_sha256", "evidence_sha256")
_PASS_FIELDS = ("before_risk_observed", "after_risk_blocked", "safe_before_passed", "safe_after_passed")
_FIELDS = set(_TEXT_FIELDS + _HASH_FIELDS + _PASS_FIELDS + ("human_reviewed",))


def _validate(record):
    if not isinstance(record, dict) or set(record) != _FIELDS:
        raise ValueError("Case record must contain exactly the required fields")
    for field in _TEXT_FIELDS:
        value = require_english(record[field])
        if not value.strip():
            raise ValueError(f"{field} must not be empty")
    for field in _HASH_FIELDS:
        if not isinstance(record[field], str) or not re.fullmatch(r"[0-9a-f]{64}", record[field]):
            raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    if record["before_sha256"] == record["after_sha256"]:
        raise ValueError("Before and after digests must differ")
    if any(record[field] is not True for field in _PASS_FIELDS):
        raise ValueError("All verifier observations must be true")
    if record["human_reviewed"] is not False:
        raise ValueError("human_reviewed must be false")
    return dict(record)


def init_store(db_path):
    """Create the internal case table and immutable-record guards if absent."""
    with closing(sqlite3.connect(db_path)) as db, db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS verified_cases (
                case_id TEXT PRIMARY KEY,
                project_identity TEXT NOT NULL,
                candidate_id TEXT NOT NULL,
                content TEXT NOT NULL UNIQUE,
                UNIQUE (project_identity, candidate_id)
            );
            CREATE TRIGGER IF NOT EXISTS verified_cases_no_update
            BEFORE UPDATE ON verified_cases BEGIN
                SELECT RAISE(ABORT, 'case records are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS verified_cases_no_delete
            BEFORE DELETE ON verified_cases BEGIN
                SELECT RAISE(ABORT, 'case records are immutable');
            END;
            CREATE TABLE IF NOT EXISTS case_revisions (
                case_id TEXT PRIMARY KEY,
                project_identity TEXT NOT NULL,
                candidate_id TEXT NOT NULL,
                verifier_id TEXT NOT NULL,
                content TEXT NOT NULL UNIQUE,
                UNIQUE (project_identity, candidate_id, verifier_id)
            );
            CREATE TRIGGER IF NOT EXISTS case_revisions_no_update
            BEFORE UPDATE ON case_revisions BEGIN
                SELECT RAISE(ABORT, 'case records are immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS case_revisions_no_delete
            BEFORE DELETE ON case_revisions BEGIN
                SELECT RAISE(ABORT, 'case records are immutable');
            END;
        """)


def promote_case(db_path, record):
    """Persist a complete verifier record, rejecting contradictory repetitions."""
    validated = _validate(record)
    content = json.dumps(validated, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    case_id = hashlib.sha256(content.encode("ascii")).hexdigest()
    init_store(db_path)
    with closing(sqlite3.connect(db_path)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        existing = db.execute(
            "SELECT case_id, content FROM verified_cases WHERE project_identity = ? AND candidate_id = ?",
            (validated["project_identity"], validated["candidate_id"]),
        ).fetchone()
        if existing:
            if json.loads(existing[1]).get("verifier_id") == validated["verifier_id"]:
                if existing != (case_id, content):
                    raise ValueError("Conflicting record for candidate and project")
            else:
                revision = db.execute(
                    "SELECT case_id, content FROM case_revisions WHERE project_identity = ? AND candidate_id = ? AND verifier_id = ?",
                    (validated["project_identity"], validated["candidate_id"], validated["verifier_id"]),
                ).fetchone()
                if revision and revision != (case_id, content):
                    raise ValueError("Conflicting verifier revision")
                if not revision:
                    db.execute("INSERT INTO case_revisions VALUES (?, ?, ?, ?, ?)",
                               (case_id, validated["project_identity"], validated["candidate_id"],
                                validated["verifier_id"], content))
        else:
            db.execute("INSERT INTO verified_cases VALUES (?, ?, ?, ?)",
                       (case_id, validated["project_identity"], validated["candidate_id"], content))
    return {"case_id": case_id, **validated}


def list_cases(db_path):
    """Read raw internal records without creating or modifying a database."""
    path = Path(db_path)
    require_english(str(path))
    if not path.exists():
        return []
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        rows = db.execute("SELECT case_id, content FROM verified_cases ORDER BY case_id").fetchall()
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='case_revisions'").fetchone():
            rows += db.execute("SELECT case_id, content FROM case_revisions ORDER BY case_id").fetchall()
    return [{"case_id": case_id, **json.loads(content)} for case_id, content in sorted(rows)]
