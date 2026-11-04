"""CVE severity for the blocking criterion: MEDIUM and above block, LOW is opt-in.

Levels come from the pinned GitHub advisory (database_specific.severity, where MODERATE
means MEDIUM), else the CVE record's CVSS base severity. They are packaged as data.
"""
from functools import lru_cache
from importlib import resources
import json

RESOURCE = "cve-severity.json"
LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
BLOCKING = {"MEDIUM", "HIGH", "CRITICAL"}


def normalize(level):
    level = str(level or "").upper()
    level = "MEDIUM" if level == "MODERATE" else level
    return level if level in LEVELS else None


def from_ghsa(record):
    return normalize((record.get("database_specific") or {}).get("severity"))


def from_cve_record(record):
    """Highest CVSS base severity in the CNA and ADP containers, or None."""
    containers = record.get("containers") or {}
    blocks = [containers.get("cna") or {}, *(containers.get("adp") or [])]
    found = [normalize(value.get("baseSeverity")) for block in blocks for metric in block.get("metrics") or []
             for key, value in metric.items() if key.startswith("cvss") and isinstance(value, dict)]
    return highest(found)


def highest(levels):
    known = [level for level in levels if level in LEVELS]
    return max(known, key=LEVELS.index) if known else None


def rule_level(cve_ids, levels):
    return highest(levels.get(cve) for cve in cve_ids)


def rule_severity(level):
    return "block" if level in BLOCKING else "review"


@lru_cache(maxsize=1)
def load_index():
    return json.loads(resources.files("paladin").joinpath("resources", RESOURCE).read_text(encoding="utf-8"))
