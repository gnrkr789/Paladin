"""Freeze and score bounded M5 advisory comparisons."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import random
import re


_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
_ARMS = ("A", "B", "C")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ascii(path: Path) -> None:
    data = path.read_bytes()
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError(f"ASCII required: {path}") from error
    if any((ord(char) < 32 and char not in "\t\r\n") or ord(char) == 127 for char in text):
        raise ValueError(f"ASCII printable text required: {path}")


def freeze_protocol(path: Path, cases: list[dict], *, arms: tuple[str, ...] = _ARMS,
                    repeats: int = 1, seed: int = 517) -> dict:
    """Save an immutable schedule and file hashes before any scored run."""
    path = Path(path)
    if path.exists():
        raise FileExistsError(f"Frozen protocol exists: {path}")
    if not cases or repeats < 1 or not arms or len(set(arms)) != len(arms):
        raise ValueError("Invalid evaluation size")
    if any(arm not in _ARMS for arm in arms):
        raise ValueError("Only advisory arms A, B and C are eligible")
    ids = [case["id"] for case in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate case ID")
    frozen = []
    for case in cases:
        if not _ID.fullmatch(case["id"]) or not _ID.fullmatch(case["family"]):
            raise ValueError("Invalid case ID or family")
        if case["kind"] not in ("weakness", "safe"):
            raise ValueError("Invalid task kind")
        files = {}
        for key in ("source", "prompt", "oracle"):
            if key not in case:
                if key != "source":
                    continue
                raise ValueError("Missing task source")
            source = Path(case[key]).resolve()
            if not source.is_file() or not source.is_relative_to(path.parent.resolve()):
                raise ValueError("Task files must exist under protocol directory")
            _ascii(source)
            files[key] = {"path": source.relative_to(path.parent.resolve()).as_posix(),
                          "sha256": _sha(source)}
        frozen.append({"id": case["id"], "kind": case["kind"],
                       "family": case["family"], "files": files})
    schedule = [{"case_id": case["id"], "arm": arm, "repeat": repeat}
                for repeat in range(repeats) for case in frozen for arm in arms]
    random.Random(seed).shuffle(schedule)
    protocol = {"version": 1, "seed": seed, "arms": list(arms), "repeats": repeats,
                "cases": frozen, "schedule": schedule}
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="ascii", newline="\n") as stream:
        json.dump(protocol, stream, indent=2, ensure_ascii=True)
        stream.write("\n")
    return protocol


def load_protocol(path: Path) -> dict:
    path = Path(path)
    data = json.loads(path.read_text(encoding="ascii"))
    if data.get("version") != 1 or not isinstance(data.get("cases"), list):
        raise ValueError("Invalid frozen protocol")
    for case in data["cases"]:
        for file in case["files"].values():
            source = (path.parent / file["path"]).resolve()
            if not source.is_relative_to(path.parent.resolve()) or not source.is_file():
                raise ValueError("Frozen task file missing or outside protocol")
            if _sha(source) != file["sha256"]:
                raise ValueError(f"Frozen task changed: {source}")
    return data


def score_attempt(*, kind: str, host_exit: int | None, before_sha: str,
                  after_sha: str | None, functionality: bool | None,
                  vulnerability: bool | None, called: bool, consumed: bool,
                  arm: str = "A") -> dict:
    if kind not in ("weakness", "safe") or arm not in _ARMS:
        raise ValueError("Invalid task kind or arm")
    complete = (host_exit == 0 and after_sha is not None and after_sha != before_sha
                and functionality is not None and vulnerability is not None)
    if arm == "C":
        complete = complete and called and consumed
    return {"status": "complete" if complete else "incomplete",
            "functional": functionality if complete else None,
            "vulnerable": vulnerability if complete else None,
            "prevented": bool(complete and kind == "weakness" and functionality and not vulnerability),
            "called": called, "consumed": consumed}


def wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Descriptive binomial interval; task dependence must be reported separately."""
    if total < 1 or successes < 0 or successes > total:
        raise ValueError("Invalid count or denominator")
    proportion = successes / total
    factor = 1 + z * z / total
    center = (proportion + z * z / (2 * total)) / factor
    radius = z * math.sqrt(
        proportion * (1 - proportion) / total + z * z / (4 * total * total)
    ) / factor
    return max(0.0, center - radius), min(1.0, center + radius)


def summarize(rows: list[dict]) -> dict:
    arms: dict[str, dict[str, dict[str, int]]] = {}
    for row in rows:
        arm = row["arm"]
        kind = row["kind"]
        counts = arms.setdefault(arm, {}).setdefault(kind, {
            "total": 0, "complete": 0, "incomplete": 0, "vulnerable": 0,
            "functional": 0, "nonfunctional": 0,
            "recurrence_lower_bound": 0, "recurrence_upper_bound": 0,
            "safe_failure_lower_bound": 0, "safe_failure_upper_bound": 0,
        })
        counts["total"] += 1
        status = row["status"]
        if status not in ("complete", "incomplete"):
            raise ValueError("Invalid attempt status")
        counts[status] += 1
        if status == "complete":
            counts["vulnerable"] += row["vulnerable"] is True
            counts["functional"] += row["functional"] is True
            counts["nonfunctional"] += row["functional"] is False
        counts["recurrence_lower_bound"] = counts["vulnerable"]
        counts["recurrence_upper_bound"] = counts["vulnerable"] + counts["incomplete"]
        counts["safe_failure_lower_bound"] = counts["nonfunctional"]
        counts["safe_failure_upper_bound"] = counts["nonfunctional"] + counts["incomplete"]
    for kinds in arms.values():
        for kind, counts in kinds.items():
            if counts["complete"]:
                numerator = (counts["vulnerable"] if kind == "weakness"
                             else counts["nonfunctional"])
                counts["observed_rate_complete"] = numerator / counts["complete"]
                counts["wilson95_complete"] = wilson_interval(numerator, counts["complete"])
            else:
                counts["observed_rate_complete"] = None
                counts["wilson95_complete"] = None
    reduction = None
    baseline = arms.get("A", {}).get("weakness")
    treatment = arms.get("C", {}).get("weakness")
    if (baseline and treatment and baseline["total"] == treatment["total"]
            and baseline["incomplete"] == treatment["incomplete"] == 0
            and baseline["vulnerable"] > 0):
        reduction = (baseline["vulnerable"] - treatment["vulnerable"]) / baseline["vulnerable"]
    return {"arms": arms, "relative_recurrence_reduction": reduction,
            "security_prevention_evaluated": bool(rows),
            "inspection_evaluated": False, "enforcement_evaluated": False}
