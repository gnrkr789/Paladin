"""Separate option containment from exact upstream argv fidelity."""
import argparse
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.target.resolve()))
    from cookiecutter import vcs
    rows = []
    for kind, values in (("hg", ("stable", "feature/topic", "v2", "--debugger=x", "--config=x", "-rdefault")),
                         ("git", ("stable", "feature/topic", "v2"))):
        for value in values:
            calls = []
            error = None

            def capture(argv, **kwargs):
                calls.append({"argv": list(argv), "shell": bool(kwargs.get("shell", False)),
                              "executable_override": kwargs.get("executable") is not None})
                return b""

            with tempfile.TemporaryDirectory() as folder:
                with patch.object(vcs, "is_vcs_installed", return_value=True), \
                        patch.object(vcs.subprocess, "check_output", side_effect=capture):
                    try:
                        vcs.clone(kind + "+https://example.invalid/template", checkout=value,
                                  clone_to_dir=folder, no_input=True)
                    except Exception as exc:
                        error = type(exc).__name__
            risk = value.startswith("-")
            shell_free = all(not call["shell"] and not call["executable_override"] for call in calls)
            checkout = [call["argv"] for call in calls if len(call["argv"]) > 1 and call["argv"][1] == "checkout"]
            rejected = error in {"RepositoryCloneFailed", "ValueError"} and not checkout
            neutralized = checkout == [[kind, "checkout", "--", value]]
            ordinary = checkout in ([[kind, "checkout", value]], [[kind, "checkout", "--", value]]) and error is None
            passed = shell_free and (rejected or neutralized if risk else ordinary)
            rows.append({"kind": kind, "value": value, "role": "risk" if risk else "ordinary",
                         "pass": passed, "rejected_before_checkout": rejected,
                         "shell_free": shell_free, "calls": calls, "error": error})
    print(json.dumps({"kind": "supplementary_containment_not_primary_rescore",
                      "source_file": str(Path(vcs.__file__).resolve()), "rows": rows,
                      "passed": sum(row["pass"] for row in rows), "total": len(rows)}))


if __name__ == "__main__":
    main()
