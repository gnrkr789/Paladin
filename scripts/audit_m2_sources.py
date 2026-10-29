"""Read-only audit of local source snapshots behind the bundled advisory pack."""
import hashlib
import json
from pathlib import Path

from paladin.knowledge import load_pack


def audit(root):
    root = Path(root).resolve()
    allowed = [(root / "data/m0/sources").resolve(), (root / "data/m2/sources").resolve()]
    pack = load_pack()
    errors = []
    count = 0
    for pattern in pack["patterns"]:
        for evidence in pattern["evidence"]:
            path = (root / evidence["snapshot_path"]).resolve()
            if not path.is_relative_to(root) or not any(path.is_relative_to(folder) for folder in allowed):
                errors.append(pattern["cve_id"] + ": snapshot path outside allowed roots")
                continue
            try:
                raw = path.read_bytes()
                if hashlib.sha256(raw).hexdigest() != evidence["sha256"]:
                    errors.append(pattern["cve_id"] + ": snapshot hash mismatch")
                if evidence["kind"] == "cve":
                    source = json.loads(raw)
                    record = source["cveMetadata"]
                    if record["cveId"] != pattern["cve_id"] or record["state"] != "PUBLISHED":
                        errors.append(pattern["cve_id"] + ": CVE metadata mismatch")
                    if pattern["version_applicability"]["source_affected"] != source["containers"]["cna"].get("affected", []):
                        errors.append(pattern["cve_id"] + ": source version claims mismatch")
                elif "anchor" in evidence:
                    anchor = evidence["anchor"]
                    if not 1 <= anchor["start_line"] <= anchor["end_line"] <= len(raw.decode("utf-8").splitlines()):
                        errors.append(pattern["cve_id"] + ": invalid patch line range")
                count += 1
            except (OSError, ValueError, KeyError) as exc:
                errors.append(pattern["cve_id"] + ": " + str(exc))
    return {"status": "PASS" if not errors else "FAIL", "patterns": len(pack["patterns"]),
            "evidence_references": count, "errors": errors,
            "scope": "snapshot integrity and identity, not vulnerability reproduction"}


if __name__ == "__main__":
    result = audit(Path(__file__).resolve().parents[1])
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["status"] == "PASS" else 1)
