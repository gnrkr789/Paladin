"""Offline CVE expansion collector: PyPI advisories (PYSEC, GHSA) joined to CVE records.

Reads local checkouts at pinned commits; advisory content is untrusted data and is
only parsed, hashed and referenced. No network access and no patch code collection.
"""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import stat

MAX_SOURCE_BYTES = 4 * 1024 * 1024
CVE_ID = re.compile(r"^CVE-(\d{4})-(\d{4,})$")
ADVISORY_ID = {"pysec": re.compile(r"^PYSEC-\d{4}-\d{1,8}$"), "ghsa": re.compile(r"^GHSA(-[a-z0-9]{4}){3}$")}
FIX_URL = re.compile(r"^https?://(github\.com/[^/\s]+/[^/\s]+/(commit/[0-9a-f]{7,40}|pull/\d+)"
                     r"|gitlab\.com/[^\s]+/-/commit/[0-9a-f]{7,40})$")
CWE_FAMILIES = {
    "path_traversal": {"CWE-22", "CWE-23", "CWE-24", "CWE-35", "CWE-36", "CWE-73"},
    "sql_injection": {"CWE-89", "CWE-564"},
    "ssrf": {"CWE-918"},
    "command_injection": {"CWE-77", "CWE-78", "CWE-88"},
    "unsafe_deserialization": {"CWE-502"},
    "xss": {"CWE-79", "CWE-80", "CWE-83", "CWE-87"},
    "open_redirect": {"CWE-601"},
    "xxe": {"CWE-611", "CWE-776", "CWE-827"},
    "redos": {"CWE-1333"},
}
FAMILY_BY_CWE = {cwe: family for family, cwes in CWE_FAMILIES.items() for cwe in cwes}


def normalize_package(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def family_for(cwe_ids):
    """Return (family, None) for exactly one mapped family, else (None, skip reason)."""
    families = {FAMILY_BY_CWE[cwe] for cwe in cwe_ids if cwe in FAMILY_BY_CWE}
    if len(families) == 1:
        return families.pop(), None
    return None, "ambiguous_family" if families else "unsupported_family"


def read_bounded(path):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SOURCE_BYTES:
        raise ValueError("not a bounded regular file")
    return path.read_bytes()


def load_yaml(data):
    import yaml  # Research-time only; the runtime package never parses YAML advisories.
    return yaml.load(data, Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader))


def _advisory(source, root, path, loader):
    """Parse one OSV advisory file into a flat record, or a parse_error record."""
    relative = path.relative_to(root).as_posix()
    try:
        data = read_bounded(path)
        record = loader(data)
        if not isinstance(record, dict) or not ADVISORY_ID[source].match(str(record.get("id"))):
            raise ValueError("missing id")
        affected = [item.get("package") or {} for item in record.get("affected") or []]
        references = [ref for ref in record.get("references") or [] if isinstance(ref, dict)]
        cwes = (record.get("database_specific") or {}).get("cwe_ids") or []
    except Exception:  # Untrusted input: any malformed file is counted, never fatal.
        return {"id": relative, "error": "parse_error"}
    aliases = [record["id"], *(alias for alias in record.get("aliases") or [] if isinstance(alias, str))]
    return {
        "id": record["id"], "source": source, "path": relative, "sha256": hashlib.sha256(data).hexdigest(),
        "pypi": any(item.get("ecosystem", "PyPI") == "PyPI" for item in affected),
        "packages": sorted({normalize_package(str(item.get("name", ""))) for item in affected
                            if item.get("ecosystem", "PyPI") == "PyPI" and item.get("name")}),
        "cve_ids": sorted({alias for alias in aliases if CVE_ID.match(alias)}),
        "cwe_ids": sorted({cwe for cwe in cwes if isinstance(cwe, str)}),
        "fix_references": sorted({ref["url"] for ref in references if isinstance(ref.get("url"), str)
                                  and (ref.get("type") == "FIX" or FIX_URL.match(ref["url"]))}),
        "withdrawn": bool(record.get("withdrawn")),
    }


def _advisories(pysec_root, ghsa_root):
    pysec_root, ghsa_root = Path(pysec_root), Path(ghsa_root)
    for path in sorted((pysec_root / "vulns").glob("*/*.yaml")):
        yield _advisory("pysec", pysec_root, path, load_yaml)
    for path in sorted((ghsa_root / "advisories" / "github-reviewed").glob("*/*/*/*.json")):
        yield _advisory("ghsa", ghsa_root, path, json.loads)


def cve_record_path(cve_id):
    """cvelistV5 layout: cves/<year>/<number // 1000>xxx/<id>.json."""
    year, number = CVE_ID.match(cve_id).groups()
    return "cves/{}/{}xxx/{}.json".format(year, int(number) // 1000, cve_id)


def _cve_record(cve_root, cve_id):
    relative = cve_record_path(cve_id)
    path = Path(cve_root) / relative
    try:
        data = read_bounded(path)
        record = json.loads(data)
    except (OSError, ValueError):
        return None
    problems = ((record.get("containers") or {}).get("cna") or {}).get("problemTypes") or []
    cwes = {item.get("cweId") for problem in problems for item in problem.get("descriptions") or []}
    return {"path": relative, "sha256": hashlib.sha256(data).hexdigest(),
            "state": (record.get("cveMetadata") or {}).get("state"),
            "cwe_ids": sorted(cwe for cwe in cwes if isinstance(cwe, str) and cwe.startswith("CWE-"))}


def _case(cve_id, advisories, cve_root, selected):
    """Return (case, None) or (None, skip reason) for one CVE and its advisories."""
    packages = sorted({name for item in advisories for name in item["packages"]})
    if not selected.intersection(packages):
        return None, "package_not_selected"
    record = _cve_record(cve_root, cve_id)
    if record is None:
        return None, "cve_record_missing"
    if record["state"] != "PUBLISHED":
        return None, "cve_not_published"
    fixes = sorted({url for item in advisories for url in item["fix_references"]})
    if not fixes:
        return None, "no_fix_reference"
    cwes = sorted({cwe for item in advisories for cwe in item["cwe_ids"]} | set(record["cwe_ids"]))
    family, reason = family_for(cwes)
    if reason:
        return None, reason
    return {
        "cve_id": cve_id, "packages": [name for name in packages if name in selected], "family": family,
        "cwe_ids": cwes, "fix_references": fixes,
        "advisories": sorted(({key: item[key] for key in ("id", "source", "path", "sha256")} for item in advisories),
                             key=lambda item: (item["source"], item["id"])),
        "cve_record": {key: record[key] for key in ("path", "sha256", "state")},
    }, None


def collect(pysec_root, ghsa_root, cve_root, packages, pins):
    """List PyPI CVEs that can become cards; count every other advisory with a reason."""
    selected = {normalize_package(name) for name in packages}
    skipped, groups = [], {}
    for item in _advisories(pysec_root, ghsa_root):
        if "error" in item:
            skipped.append((item["id"], None, item["error"]))
        elif not item["pypi"]:
            continue
        elif item["withdrawn"]:
            skipped.append((item["id"], (item["cve_ids"] or [None])[0], "withdrawn"))
        elif not item["cve_ids"]:
            skipped.append((item["id"], None, "no_cve_id"))
        else:
            for cve_id in item["cve_ids"]:
                groups.setdefault(cve_id, []).append(item)
    cases = []
    for cve_id in sorted(groups):
        case, reason = _case(cve_id, groups[cve_id], cve_root, selected)
        if case:
            cases.append(case)
        else:
            skipped += [(item["id"], cve_id, reason) for item in groups[cve_id]]
    skipped.sort(key=lambda entry: (entry[0], entry[1] or ""))
    return {
        "schema_version": 1, "sources": dict(sorted(pins.items())), "packages": sorted(selected),
        "cases": cases, "family_counts": dict(sorted(Counter(case["family"] for case in cases).items())),
        "skipped": dict(sorted(Counter(reason for _, _, reason in skipped).items())),
        "skipped_items": [{"advisory": ident, "cve_id": cve_id, "reason": reason}
                          for ident, cve_id, reason in skipped],
    }
