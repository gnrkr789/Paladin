"""Build prevention pack v2: verified patterns kept as they are, candidate cards added.

Candidate evidence is a byte-exact copy of the pinned advisory and CVE files (CC-BY-4.0
and CVE Terms of Use), linked to the commit they were read at. Fix commits stay URLs.
"""
import copy
import hashlib
from pathlib import Path

from paladin.cve_collect import read_bounded

REPOSITORIES = {"pysec": "https://github.com/pypa/advisory-database",
                "ghsa": "https://github.com/github/advisory-database",
                "cvelist": "https://github.com/CVEProject/cvelistV5"}
PACK_ID = "python-web-prevention-v2"


def _origin(source_id):
    if source_id.startswith("GHSA-"):
        return "ghsa"
    if source_id.startswith("PYSEC-"):
        return "pysec"
    return "cvelist"


def copy_evidence(card, roots, pins, dest, folder):
    """Copy each card source into dest/folder at its recorded hash; return evidence entries."""
    evidence = []
    for source in card["sources"]:
        origin = _origin(source["id"])
        data = read_bounded(Path(roots[origin]) / source["path"])
        if hashlib.sha256(data).hexdigest() != source["sha256"]:
            raise ValueError("source hash mismatch: " + source["path"])
        relative = "{}/{}{}".format(folder, source["id"], Path(source["path"]).suffix)
        target = Path(dest) / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        evidence.append({"kind": "cve" if origin == "cvelist" else "advisory",
                         "url": "{}/blob/{}/{}".format(REPOSITORIES[origin], pins[origin], source["path"]),
                         "snapshot_path": relative, "sha256": source["sha256"]})
    return evidence


def candidate_pattern(card, evidence, date, review=None):
    """Candidate pattern; a patch_checked review promotes it and applies its revised text,
    or the later correction of that text when there is one."""
    checked = bool(review) and review["outcome"] == "patch_checked"
    revision = checked and (review.get("corrected") or review["revised"])
    text = dict(card, **revision) if revision else card
    pattern = {"pattern_id": card["cve_id"], "cve_id": card["cve_id"], "family": card["family"], "language": "python",
               "title": card["title"], "cause": text["cause"], "preconditions": text["preconditions"],
               "prevention": text["prevention"], "limitations": text["limitations"], "record_state": "PUBLISHED",
               "verification_status": "patch_checked" if checked else "candidate",
               "source_review": {"kind": "model_advisory_draft", "reviewer": card["drafter"], "date": date},
               "enforcement_enabled": False, "sharing_enabled": False,
               "fixtures": [{"role": role, "scenario": card["fixtures"][role], "status": "specification_only"}
                            for role in ("risk", "safe")],
               "evidence": evidence, "fix_references": card["fix_references"], "packages": card["packages"],
               "cwe_ids": card["cwe_ids"], "citations": card["citations"]}
    if checked:
        pattern["patch_review"] = {"reviewer": review["reviewer"], "date": review["date"],
                                   "observation": review["recheck_observation"] or review["observation"],
                                   "card_revised": bool(review["revised"]), "patches": review["patches"]}
    return pattern


def build_pack(base, cards, date, reviews=None):
    """base pack + (card, evidence) pairs: verified patterns first in their order, then
    candidates by id; a CVE already in base keeps its verified pattern."""
    pack = copy.deepcopy(base)
    reviews = reviews or {}
    known = {pattern["cve_id"] for pattern in pack["patterns"]}
    pack["patterns"] += sorted((candidate_pattern(card, evidence, date, reviews.get(card["cve_id"]))
                                for card, evidence in cards if card["cve_id"] not in known),
                               key=lambda pattern: pattern["pattern_id"])
    pack.update(pack_id=PACK_ID, created_on=date)
    return pack


def split_withdrawn(cards, collection, history, date):
    """Cards still collected stay active; the rest leave the pack, recorded once with a reason."""
    active_ids = {case["cve_id"] for case in collection["cases"]}
    reasons = {item["cve_id"]: item["reason"] for item in collection["skipped_items"] if item["cve_id"]}
    records = {item["cve_id"]: item for item in history}
    active = []
    for card in cards:
        if card["cve_id"] in active_ids:
            active.append(card)
        elif card["cve_id"] not in records:
            records[card["cve_id"]] = {"cve_id": card["cve_id"], "reason": reasons.get(card["cve_id"], "not_collected"),
                                       "date": date}
    return active, [records[key] for key in sorted(records)]
