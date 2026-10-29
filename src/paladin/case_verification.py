"""Before/after checks using an external isolated process observer."""
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tempfile

from paladin.candidate_scan import RULE_ID, scan_project
from paladin.pip_case_adapter import RULE_ID as PIP_RULE_ID
from paladin.language import require_english

VERIFIER_ID = "mercurial-isolated-observer-v6"
MAX_SOURCE_BYTES = 1_000_000
PROBE_CASES = (("hg", "--config=alias.checkout=x", "risk"), ("hg", "--debugger", "risk"),
               ("hg", "-rdefault", "risk"), ("hg", "stable", "ordinary"),
               ("git", "stable", "ordinary"), ("hg", "--literal-branch", "literal"))
# "-rdefault" is not an early Mercurial option after pip's "-r" flag, so pip uses
# only the globally parsed early options as risk inputs.
PIP_PROBE_CASES = (("hg", "--config=alias.update=x", "risk"), ("hg", "--debugger", "risk"),
                   ("hg", "stable", "ordinary"), ("hg", "--literal-branch", "literal"))
CHECKOUT_PARENT = "/work/case"


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _source(root, relative):
    root = Path(root).absolute()
    require_english(str(root))
    require_english(relative)
    parts = PurePosixPath(relative).parts
    if not parts or any(part in (".", "..") or "\\" in part or ":" in part for part in parts):
        raise ValueError("invalid_source_path")
    if PurePosixPath(relative).is_absolute():
        raise ValueError("invalid_source_path")
    item = root
    for part in (None, *parts):
        if part is not None:
            item = item / part
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("linked_source_path")
    if not item.resolve().is_relative_to(root.resolve()) or not item.is_file():
        raise ValueError("invalid_source_path")
    if info.st_size > MAX_SOURCE_BYTES:
        raise ValueError("source_too_large")
    with item.open("rb") as stream:
        data = stream.read(MAX_SOURCE_BYTES + 1)
    if len(data) > MAX_SOURCE_BYTES:
        raise ValueError("source_too_large")
    return item, data


def _validate(before, after, candidate):
    if Path(before).resolve() == Path(after).resolve():
        raise ValueError("distinct_project_copies_required")
    if (candidate.get("rule_id"), candidate.get("cve_id")) not in {
            (RULE_ID, "CVE-2022-24065"),
            ("CVE-2023-5752:mercurial-revision-v1", "CVE-2023-5752")}:
        raise ValueError("unsupported_rule")
    relative = candidate.get("path", "")
    suffix = "cookiecutter/vcs.py" if candidate["rule_id"] == RULE_ID else "pip/_internal/vcs/mercurial.py"
    if not relative.endswith(suffix):
        raise ValueError("unsupported_project_adapter")
    before_path, before_bytes = _source(before, relative)
    after_path, after_bytes = _source(after, relative)
    if os.path.samefile(before_path, after_path):
        raise ValueError("hardlinked_project_copies")
    if _sha(before_bytes) != candidate.get("source_sha256"):
        raise ValueError("candidate_source_changed")
    return before_path, before_bytes, after_path, after_bytes


def _repair_bytes(original, rule_id):
    """Dispatch the deterministic repair by rule, the same key that selects the adapter."""
    if rule_id == PIP_RULE_ID:
        from paladin.pip_case_adapter import repair_bytes
        return repair_bytes(original)
    if rule_id != RULE_ID:
        raise ValueError("unsupported_rule")
    tree = ast.parse(original)
    choices = []
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) or function.name != "clone":
            continue
        for node in ast.walk(function):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            func, argv = node.func, node.args[0]
            if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                    and func.value.id == "subprocess" and func.attr == "check_output"
                    and isinstance(argv, ast.List) and len(argv.elts) == 3
                    and isinstance(argv.elts[0], ast.Name) and isinstance(argv.elts[1], ast.Constant)
                    and argv.elts[1].value == "checkout" and isinstance(argv.elts[2], ast.Name)):
                choices.append(argv)
    if len(choices) != 1:
        raise ValueError("unsupported_repair_shape")
    argv = choices[0]
    executable, value = argv.elts[0].id, argv.elts[2].id
    replacement = ("[" + executable + ", 'checkout', *(['--'] if " + executable
                   + " == 'hg' else []), " + value + "]").encode("ascii")
    lines = original.splitlines(keepends=True)
    start = sum(map(len, lines[:argv.lineno - 1])) + argv.col_offset
    end = sum(map(len, lines[:argv.end_lineno - 1])) + argv.end_col_offset
    repaired = original[:start] + replacement + original[end:]
    ast.parse(repaired)
    return repaired


def propose_repair(before, after, candidate):
    """Apply the narrow source-preserving change only to an identical copy."""
    before_path, original, destination, copy = _validate(before, after, candidate)
    if original != copy:
        raise ValueError("repair_copy_not_identical")
    repaired = _repair_bytes(original, candidate["rule_id"])
    if _sha(before_path.read_bytes()) != candidate["source_sha256"] or destination.read_bytes() != copy:
        raise ValueError("source_changed_during_repair")
    descriptor, temporary = tempfile.mkstemp(prefix=".paladin-repair-", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(repaired)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {"before_sha256": _sha(original), "after_sha256": _sha(repaired),
            "repair_kind": ("mercurial-option-terminator-v1" if candidate["rule_id"] == RULE_ID
                            else "mercurial-attached-revision-v1"), "target_path": candidate["path"]}


def probe_cases(adapter="cookiecutter"):
    if adapter not in ("cookiecutter", "pip-mercurial"):
        raise ValueError("unsupported_adapter")
    table = PROBE_CASES if adapter == "cookiecutter" else PIP_PROBE_CASES
    return [dict(kind=kind, value=value, role=role) for kind, value, role in table]


def _expected(adapter, kind, value):
    """Exact clone, exposed and protected argv for one adapter and case."""
    source, checkout = "/fixtures/" + kind + "source", CHECKOUT_PARENT + "/" + kind + "source"
    if adapter == "cookiecutter":
        protected = [kind, "checkout", "--", value] if kind == "hg" else [kind, "checkout", value]
        return ([kind, "clone", source], CHECKOUT_PARENT, [kind, "checkout", value], protected)
    return (["hg", "clone", "--noupdate", "--quiet", source, checkout], None,
            ["hg", "update", "--quiet", "-r", value], ["hg", "update", "--quiet", "--rev=" + value])


def _allowed_helpers(kind):
    """Exact helper execs that local Git clone performs for the fixture; none for Mercurial."""
    if kind != "git":
        return []
    command = "git-upload-pack '/fixtures/gitsource/.git'"
    return [("/bin/sh", ["/bin/sh", "-c", command, command]),
            ("/usr/lib/git-core/git-upload-pack", ["git-upload-pack", "/fixtures/gitsource/.git"])]


def _observed_calls(row):
    """Re-derive calls from the stored root-owned trace; never trust parsed copies."""
    from paladin.sandbox_runtime import trace_grammar
    trace = row.get("trace")
    if not isinstance(trace, str) or _sha(trace.encode("ascii", "strict")) != row.get("trace_sha256"):
        raise ValueError("invalid_observer_trace")
    parsed = trace_grammar().parse_trace(trace, row.get("target_pid"), row.get("target_cwd"))
    if (parsed["calls"] != row.get("calls") or parsed["target_exit_code"] != row.get("target_exit_code")
            or parsed["path_alias_created"] != row.get("path_alias_created")):
        raise ValueError("invalid_observer_calls")
    return parsed


def derive_checks(old, new, adapter="cookiecutter"):
    """Derive bounded argument properties from authenticated OS observations."""
    expected = probe_cases(adapter)
    def parse(output):
        rows = output.get("observations")
        if not isinstance(rows, list) or len(rows) != len(expected):
            raise ValueError("invalid_observer_outcomes")
        observations = []
        for row, case in zip(rows, expected):
            if any(row.get(key) != value for key, value in case.items()):
                raise ValueError("invalid_observer_case")
            kind, value, role = case["kind"], case["value"], case["role"]
            calls = _observed_calls(row)["calls"]
            if len(calls) > 64:
                raise ValueError("invalid_observer_calls")
            clone_argv, clone_cwd, exposed_argv, protected_argv = _expected(adapter, kind, value)
            # A call counts only when the kernel-executed binary matches argv[0] and the case.
            unexpected = any((call["exec_path"], call["argv"]) not in _allowed_helpers(kind)
                             and (call["exec_path"] != "/usr/bin/" + kind or call["argv"][0] != kind)
                             for call in calls)
            clones = [call for call in calls if call["argv"][1:2] == ["clone"]]
            checkout = [call for call in calls if call["argv"][1:2] in (["checkout"], ["update"])]
            cloned = (len(clones) == 1 and clones[0]["argv"] == clone_argv and clones[0]["exit_code"] == 0
                      and (clone_cwd is None or clones[0]["cwd"] == clone_cwd))
            # The decisive exec must carry the launcher environment unchanged.
            located = (cloned and len(checkout) == 1
                       and checkout[0]["cwd"] == CHECKOUT_PARENT + "/" + kind + "source"
                       and checkout[0]["env_sha256"] is not None
                       and checkout[0]["env_sha256"] == row.get("launcher_env_sha256"))
            args = checkout[0]["argv"] if located else []
            bound = not unexpected and located
            # The functional outcome comes only from the observer's root replay of the
            # observed argv in a clean clone, never from target-writable checkout files.
            safe = (bound and checkout[0]["exit_code"] == 0 and row.get("target_exit_code") == 0
                    and row.get("safe_ok") is True and row.get("path_alias_created") is False
                    and row.get("checkout_directory_real") is True
                    and row.get("replayed_argv") == args and row.get("replay_branch") == value)
            observations.append(dict(role=role, exposed=bound and args == exposed_argv,
                                     protected=bound and args == protected_argv, safe=safe))
        return observations
    before, after = parse(old), parse(new)
    return {"before_risk_observed": all(row["exposed"] for row in before if row["role"] == "risk"),
            "after_risk_blocked": all(row["protected"] for row in after if row["role"] == "risk"),
            "safe_before_passed": all(row["safe"] for row in before if row["role"] == "ordinary"),
            "safe_after_passed": all(row["safe"] for row in after if row["role"] != "risk")
                                 and all(row["protected"] for row in after if row["role"] == "literal")}


def verify_case(before, after, candidate, *, runtime=None):
    """Run untrusted source only in the explicitly configured Docker boundary."""
    from paladin.sandbox_runtime import run_observed
    before_path, before_bytes, after_path, after_bytes = _validate(before, after, candidate)
    if before_bytes == after_bytes:
        raise ValueError("repair_unchanged")
    if after_bytes != _repair_bytes(before_bytes, candidate["rule_id"]):
        raise ValueError("verification_repair_shape_not_supported")
    observed = [item for item in scan_project(before)["candidates"]
                if item["candidate_id"] == candidate.get("candidate_id")]
    if len(observed) != 1 or observed[0] != candidate:
        raise ValueError("verification_candidate_binding_mismatch")
    if not isinstance(runtime, dict):
        raise ValueError("sandbox_runtime_not_configured")
    adapter = "cookiecutter" if candidate["rule_id"] == RULE_ID else "pip-mercurial"
    cases = probe_cases(adapter)
    old = run_observed(before_bytes, runtime["image_id"], cases, adapter=adapter)
    new = run_observed(after_bytes, runtime["image_id"], cases, adapter=adapter)
    if _sha(before_path.read_bytes()) != _sha(before_bytes) or _sha(after_path.read_bytes()) != _sha(after_bytes):
        raise ValueError("source_changed_during_probe")
    flags = derive_checks(old, new, adapter)
    evidence = {"verifier_id": VERIFIER_ID, "before_sha256": _sha(before_bytes),
                "after_sha256": _sha(after_bytes), "before": old, "after": new, "checks": flags,
                "candidate": candidate, "runtime": runtime, "adapter": adapter,
                "limitations": ["Isolated source-adapter checks, not whole-project security approval.",
                                "Only the recorded argument-injection cases and safe branches are tested.",
                                "Host authentication does not defend against a principal that can write the host key."]}
    record = {"candidate_id": candidate["candidate_id"], "cve_id": candidate["cve_id"],
              "rule_id": candidate["rule_id"],
              "project_identity": _sha((str(Path(before).resolve()) + "|" + candidate["path"]).encode("ascii")),
              "before_sha256": _sha(before_bytes), "after_sha256": _sha(after_bytes),
              "verifier_id": VERIFIER_ID, "evidence_sha256": _sha(json.dumps(
                  evidence, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")),
              **flags, "human_reviewed": False}
    return {"status": "verified" if all(flags.values()) else "not_verified",
            "record": record, "evidence": evidence}
