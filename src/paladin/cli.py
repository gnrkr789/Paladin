"""Paladin local command-line entry point."""
import argparse
import json
import sys
from pathlib import Path

from paladin.local import doctor, setup


def _case_error(exc):
    """Expose fixed reason codes without untrusted target or Docker text."""
    known = {
        "runtime_not_configured", "runtime_build_context_changed", "runtime_observer_identity_changed",
        "runtime_requires_immutable_image_id", "runtime_invalid_identity", "runtime_invalid_digest",
        "runtime_linked_path", "runtime_path_not_regular", "runtime_state_too_large", "runtime_invalid_json",
        "sandbox_docker_unavailable_or_timeout", "sandbox_docker_failed", "sandbox_image_build_failed",
        "sandbox_build_unavailable_or_timeout", "sandbox_requires_immutable_image_id",
        "sandbox_observer_not_ready", "sandbox_observation_failed", "sandbox_execution_failed",
        "sandbox_invalid_observer_credentials", "candidate_missing_or_changed", "invalid_candidate_id",
        "evidence_conflict", "evidence_identity_mismatch", "evidence_source_changed",
        "unsupported_source_identity", "unsupported_candidate", "unsupported_adapter",
        "invalid_source_path", "linked_source_path", "source_too_large", "unsupported_rule",
        "unsupported_project_adapter", "candidate_source_changed", "unsupported_repair_shape",
        "repair_copy_not_identical", "source_changed_during_repair", "repair_unchanged",
        "verification_repair_shape_not_supported", "verification_candidate_binding_mismatch",
        "sandbox_runtime_not_configured", "source_changed_during_probe", "runtime_policy_changed",
        # Host-side observer payload and trace checks (fixed Paladin identifiers).
        "sandbox_invalid_case_identity", "sandbox_trace_integrity_failed", "sandbox_trace_parse_disagrees",
        "sandbox_invalid_source", "sandbox_invalid_cases", "sandbox_invalid_adapter", "sandbox_invalid_case",
        "invalid_observer_trace", "invalid_observer_calls", "invalid_observer_outcomes", "invalid_observer_case",
        "unsupported_trace_line", "trace_record_interrupted", "trace_resume_without_start",
        "trace_non_ascii_string", "trace_not_ascii", "trace_root_invalid", "trace_argv_invalid",
        "trace_child_identity_invalid", "untraced_clone_observed", "unexpected_traced_syscall",
        "unsupported_exec_trace_shape", "unsupported_chdir_shape", "unsupported_clone_shape",
        "unsupported_clone_flags", "unsupported_symlink_shape", "unsupported_rename_shape",
    }
    code = str(exc).split(":", 1)[0]
    return code if code in known else "case_operation_failed"


def main(argv=None):
    parser = argparse.ArgumentParser(prog="paladin")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ["setup", "doctor"]:
        command = commands.add_parser(name)
        command.add_argument("--workspace", type=Path, default=Path.cwd())
        command.add_argument("--json", action="store_true")
        if name == "setup":
            command.add_argument("--no-start", action="store_true", help="write local configuration without starting Docker")
        else:
            command.add_argument("--semantic", action="store_true", help="also verify the M2 model and pattern index")
    model = commands.add_parser("model")
    model.add_argument("action", choices=["prepare"])
    patterns = commands.add_parser("patterns")
    patterns.add_argument("action", choices=["validate", "index", "status", "export"])
    search = commands.add_parser("search")
    search.add_argument("query", help="English technical text only (printable ASCII)")
    search.add_argument("--limit", type=int, default=5)
    search.add_argument("--family")
    hook = commands.add_parser("hook", help="agent hook adapters for change-time checks")
    hook.add_argument("action", choices=["claude-code", "codex", "install"])
    hook.add_argument("--workspace", type=Path, default=Path.cwd())
    hook.add_argument("--host", choices=["claude-code", "codex"], default="claude-code")
    mcp = commands.add_parser("mcp", help="serve bounded advisory tools over stdio")
    mcp.add_argument("--workspace", type=Path, default=Path.cwd())
    cases = commands.add_parser("cases", help="scan and verify locally supported CVE cases")
    cases.add_argument("action", choices=["scan", "auto", "list", "runtime-build"])
    cases.add_argument("--project", type=Path, default=Path.cwd())
    cases.add_argument("--workspace", type=Path, default=Path.cwd())
    cases.add_argument("--json", action="store_true")
    cases.add_argument("--cve", choices=["CVE-2022-24065", "CVE-2023-5752"])
    for command in [model, patterns, search]:
        command.add_argument("--workspace", type=Path, default=Path.cwd())
        command.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "hook":
        from paladin import agent_hook
        if args.action in agent_hook.HOSTS:
            return agent_hook.main(args.workspace, sys.stdin, sys.stdout, host=args.action)
        try:
            # -I: isolated mode, so modules in the hooked workspace cannot shadow Paladin.
            result = agent_hook.install_hook(args.workspace, [sys.executable, "-I", "-m", "paladin.cli"], args.host)
        except (OSError, ValueError) as exc:
            print(json.dumps({"status": "unavailable", "error": str(exc).split(":", 1)[0][:200]}, indent=2))
            return 1
        print(json.dumps(result, indent=2))
        return 0
    if args.command == "mcp":
        from paladin.mcp_server import main as serve_mcp
        serve_mcp(args.workspace)
        return 0
    try:
        if args.command == "setup":
            result = setup(args.workspace, start=not args.no_start)
        elif args.command == "doctor":
            result = doctor(args.workspace)
            if args.semantic:
                from paladin.knowledge import knowledge_status
                result["semantic"] = knowledge_status(args.workspace)
                if result["status"] == "ready" and result["semantic"]["status"] != "ready":
                    result["status"] = "degraded"
        elif args.command == "model":
            from paladin.embedding import prepare_model
            result = prepare_model(args.workspace)
        elif args.command == "cases":
            from paladin.candidate_scan import scan_project
            from paladin.case_pipeline import run_case, verified_case_references
            if args.action == "runtime-build":
                from paladin.case_runtime import configure_runtime
                identity = configure_runtime(args.workspace)
                result = {"status": "ready", "runtime": identity}
            elif args.action == "list":
                references = [verified_case_references(args.workspace, cve) for cve in
                              ([args.cve] if args.cve else ["CVE-2022-24065", "CVE-2023-5752"])]
                result = {"status": "complete" if all(item["status"] == "complete" for item in references) else "partial",
                          "cases": [case for item in references for case in item["cases"]]}
            else:
                result = scan_project(args.project)
                if args.action == "auto":
                    runs = []
                    for candidate in result["candidates"]:
                        if candidate.get("verifiable") is False:
                            # Review-level findings have no execution adapter; never run them.
                            runs.append({"status": "review_only", "candidate_id": candidate["candidate_id"],
                                         "reason": "no_verification_adapter"})
                            continue
                        try:
                            runs.append(run_case(args.workspace, args.project, candidate["candidate_id"]))
                        except (ValueError, OSError, TimeoutError) as exc:
                            runs.append({"status": "not_verified", "candidate_id": candidate["candidate_id"],
                                         "reason": _case_error(exc)})
                    result["case_runs"] = runs
                    if any(item["status"] != "promoted" for item in runs):
                        result["status"] = "partial"
            result["notice"] = ("Only the Cookiecutter CVE-2022-24065 and pip Mercurial CVE-2023-5752 "
                                "adapters are supported; no security verdict.")
        elif args.command == "patterns":
            from paladin.knowledge import load_pack, build_index, knowledge_status, verification_counts
            if args.action == "validate":
                pack = load_pack()
                result = {"status": "valid", "pack_id": pack["pack_id"], "pattern_count": len(pack["patterns"]),
                          "verification_counts": verification_counts(pack), "enforcement_enabled": False}
            elif args.action == "export":
                from paladin.knowledge import export_snapshot
                result = export_snapshot(args.workspace)
            else:
                result = (build_index if args.action == "index" else knowledge_status)(args.workspace)
        else:
            from paladin.knowledge import search_patterns
            result = search_patterns(args.workspace, args.query, limit=args.limit, family=args.family)
    except Exception as exc:
        result = {"status": "unavailable", "security_ready": False,
                  "error": _case_error(exc) if args.command == "cases" else f"{type(exc).__name__}: {str(exc)[:600]}"}
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"Paladin {args.command}: {result['status']}")
        for name, check in result.get("checks", {}).items():
            print(f"  {name}: {check['status']}" + (f" ({check['detail']})" if "detail" in check else ""))
        if "error" in result:
            print(result["error"])
        for match in result.get("matches", []):
            pattern = match["pattern"]
            print(f"  {pattern['cve_id']} ({match['cosine_similarity']:.3f}) {pattern['title']}")
            print("    Conditions: " + " ".join(pattern["preconditions"]))
            print("    Prevention: " + pattern["prevention"])
        if "semantic" in result:
            print("  semantic: " + result["semantic"]["status"])
        for candidate in result.get("candidates", []):
            print("  candidate: " + candidate["path"] + ":" + str(candidate["line"]))
        for case in result.get("case_runs", []):
            print("  case: " + case["status"])
        print(result.get("notice", "Advisory tooling; security prevention and blocking are not ready."))
    return 0 if result["status"] in {"ready", "configured", "prepared", "indexed", "valid", "complete", "exported"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
