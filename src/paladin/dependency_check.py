"""Pinned dependency versions against the affected ranges of the collected advisories.

Static data only: no model, network or index. Ranges come from the PYSEC and GHSA records
(OSV format) that the collector pinned; they are packaged as dependency-advisories.json.
A finding means the pinned version is in an advisory's affected range, not that the
project uses the vulnerable feature.
"""
from functools import lru_cache
from importlib import resources
import json
from pathlib import Path
import re
import tomllib


RESOURCE = "dependency-advisories.json"
MAX_BYTES = 2_000_000
LOCKS = {"uv.lock", "poetry.lock", "Pipfile.lock"}
_REQUIREMENTS = re.compile(r"(^|/)(requirements[^/]*\.txt|requirements/[^/]+\.txt)$", re.IGNORECASE)
_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")
_PIN = re.compile(r"^(===|==)\s*([^\s,;*]+)$")


def normalize(name):
    """PEP 503 project name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _pairs(events):
    pairs, current = [], None
    for event in events:
        if "introduced" in event:
            current = {"introduced": event["introduced"]}
            pairs.append(current)
        elif current is not None and ("fixed" in event or "last_affected" in event):
            key = "fixed" if "fixed" in event else "last_affected"
            current[key] = event[key]
            current = None
    return pairs


def affected_entries(record):
    """PyPI packages, ECOSYSTEM ranges and (without ranges) explicit versions of one OSV record."""
    entries = []
    for item in record.get("affected") or []:
        package = item.get("package") or {}
        if package.get("ecosystem") != "PyPI" or not package.get("name"):
            continue
        ranges = [pair for block in item.get("ranges") or [] if block.get("type") == "ECOSYSTEM"
                  for pair in _pairs(block.get("events") or [])]
        entries.append({"package": normalize(package["name"]), "ranges": ranges,
                        "versions": [] if ranges else list(item.get("versions") or [])})
    return entries


def _version(text):
    # Imported here so the change hook pays for packaging only when it checks versions.
    from packaging.version import InvalidVersion, Version
    try:
        return Version(text)
    except (InvalidVersion, TypeError):
        return None


def _in_range(version, pair):
    start = _version("0" if pair["introduced"] == "0" else pair["introduced"])
    if start is None or version < start:
        return False
    if "fixed" in pair:
        end = _version(pair["fixed"])
        return end is not None and version < end
    if "last_affected" in pair:
        end = _version(pair["last_affected"])
        return end is not None and version <= end
    return True


def is_affected(version, entry):
    parsed = _version(version)
    if parsed is None:
        return False
    if any(_in_range(parsed, pair) for pair in entry["ranges"]):
        return True
    return any(_version(item) == parsed for item in entry["versions"])


def _requirement(line):
    """(name, version) for an exact pin, (name, None) for any other requirement, None for noise."""
    line = line.split(" #", 1)[0].split(";", 1)[0].split(" --", 1)[0].strip().rstrip("\\").strip()
    if not line or line.startswith(("#", "-")) or "://" in line or line.startswith(("git+", ".", "/")):
        return None
    match = _NAME.match(line)
    if not match:
        return None
    pin = _PIN.match(match.group(3).strip())
    return normalize(match.group(1)), pin.group(2) if pin else None


def parse_requirements(text):
    pins, unpinned = [], []
    for number, line in enumerate(text.splitlines(), 1):
        parsed = _requirement(line)
        if parsed and parsed[1]:
            pins.append((parsed[0], parsed[1], number))
        elif parsed:
            unpinned.append((parsed[0], number))
    return pins, unpinned


def _pyproject_requirements(data):
    project = data.get("project") or {}
    groups = [project.get("dependencies") or [], *(project.get("optional-dependencies") or {}).values(),
              *(data.get("dependency-groups") or {}).values()]
    return [line for group in groups if isinstance(group, list) for line in group]


def parse_pyproject(text):
    """Pins from project dependencies, optional dependencies and dependency groups."""
    pins, unpinned = [], []
    for line in _pyproject_requirements(tomllib.loads(text)):
        parsed = _requirement(line) if isinstance(line, str) else None
        if parsed and parsed[1]:
            pins.append((parsed[0], parsed[1], None))
        elif parsed:
            unpinned.append((parsed[0], None))
    return pins, unpinned


def parse_lock(name, text):
    if name == "Pipfile.lock":
        data = json.loads(text)
        return [(normalize(package), spec["version"].lstrip("="), None)
                for section in ("default", "develop") for package, spec in (data.get(section) or {}).items()
                if isinstance(spec, dict) and isinstance(spec.get("version"), str)]
    return [(normalize(item["name"]), str(item["version"]), None) for item in tomllib.loads(text).get("package") or []
            if isinstance(item, dict) and item.get("name") and item.get("version")]


def is_dependency_file(path):
    path = str(path).replace("\\", "/")
    name = path.rsplit("/", 1)[-1]
    return name in LOCKS or name == "pyproject.toml" or bool(_REQUIREMENTS.search(path))


@lru_cache(maxsize=1)
def load_index():
    return json.loads(resources.files("paladin").joinpath("resources", RESOURCE).read_text(encoding="utf-8"))


def _by_package(index):
    table = {}
    for entry in index["entries"]:
        table.setdefault(entry["package"], []).append(entry)
    return table


def check_text(path, text, index=None):
    """Findings for one dependency file's text; the file kind comes from its name."""
    index = index or load_index()
    name = str(path).replace("\\", "/").rsplit("/", 1)[-1]
    if name in LOCKS:
        pins, unpinned = parse_lock(name, text), []
    elif name == "pyproject.toml":
        pins, unpinned = parse_pyproject(text)
    else:
        pins, unpinned = parse_requirements(text)
    table, findings, notes = _by_package(index), [], []
    for package, version, line in pins:
        if _version(version) is None:
            notes.append("{} {}: not a PEP 440 version; skipped".format(package, version))
            continue
        for entry in table.get(package, []):
            if is_affected(version, entry):
                findings.append({"file": str(path).replace("\\", "/"), "line": line, "package": package,
                                 "version": version, "cve_id": entry["cve_id"], "title": entry["title"],
                                 "fixed_in": sorted({pair["fixed"] for pair in entry["ranges"] if "fixed" in pair},
                                                    key=lambda item: _version(item) or _version("0"))})
    return {"findings": findings, "unpinned": list(dict.fromkeys(package for package, _ in unpinned)),
            "notes": notes, "checked": len(pins)}


def _discover(root):
    candidates = [path for path in root.iterdir() if path.is_file() and is_dependency_file(path.name)]
    folder = root / "requirements"
    if folder.is_dir():
        candidates += [path for path in folder.glob("*.txt") if path.is_file()]
    return sorted(candidates)


def check_workspace(root, paths=None, index=None):
    """Check the workspace's dependency files (or the given workspace-relative ones)."""
    root = Path(root).resolve()
    files = _discover(root) if paths is None else [root / path for path in paths]
    results, notes = [], []
    for path in files:
        try:
            resolved = path.resolve()
            if not resolved.is_relative_to(root) or path.is_symlink() or not resolved.is_file():
                notes.append("{}: outside the workspace, a link, or not a file; skipped".format(path.name))
                continue
            if resolved.stat().st_size > MAX_BYTES or not is_dependency_file(resolved.relative_to(root).as_posix()):
                notes.append("{}: not a supported dependency file or too large; skipped".format(path.name))
                continue
            result = check_text(resolved.relative_to(root).as_posix(), resolved.read_text(encoding="utf-8"), index)
        except (OSError, UnicodeDecodeError, ValueError, tomllib.TOMLDecodeError) as exc:
            notes.append("{}: could not be read ({})".format(path.name, type(exc).__name__))
            continue
        results.append(dict(result, file=resolved.relative_to(root).as_posix()))
    findings = [finding for result in results for finding in result["findings"]]
    status = "findings" if findings else "clean" if results else "no_dependency_files"
    return {"status": status, "findings": findings, "files": [r["file"] for r in results],
            "unpinned": {r["file"]: r["unpinned"] for r in results if r["unpinned"]},
            "notes": notes + [note for r in results for note in r["notes"]],
            "limitations": ["Pinned versions against collected PyPI advisory ranges only; unpinned requirements "
                            "are listed, not judged. An affected version does not show the vulnerable feature "
                            "is used. A clean result is not a security verdict."]}
