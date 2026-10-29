"""Private prospective boundary checks on full third-party project checkouts."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch


def check_cookiecutter():
    from cookiecutter import vcs
    rows = []
    for kind in ("git", "hg"):
        for value in ("release-2026", "feature/topic", "v2.1.0", "--debugger=x",
                      "--config=alias.checkout=!echo", "-rdefault"):
            calls = []
            with tempfile.TemporaryDirectory() as folder:
                with patch.object(vcs, "is_vcs_installed", return_value=True), \
                        patch.object(vcs.subprocess, "check_output",
                                     side_effect=lambda argv, **kwargs: calls.append(list(argv)) or b""):
                    try:
                        vcs.clone(kind + "+https://example.invalid/template", checkout=value,
                                  clone_to_dir=folder, no_input=True)
                        observed = calls[-1]
                    except Exception as error:
                        observed = type(error).__name__
            expected = [kind, "checkout"] + (["--"] if kind == "hg" else []) + [value]
            # A shell-free argv remains a compatibility requirement. Only hg
            # requires the upstream option-terminator correction in this task.
            safe_original = [kind, "checkout", value]
            passed = observed == expected or (not value.startswith("-") and observed == safe_original)
            rows.append({"id": kind + ":" + value, "role": "risk" if kind == "hg" and value.startswith("-") else "safe",
                         "pass": passed, "observed": observed, "expected": expected})
    return rows, vcs.__file__


def check_django():
    from django.conf import settings
    settings.configure(DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
                       INSTALLED_APPS=[], USE_TZ=False)
    import django
    django.setup()
    from django.db import connection
    from django.db.models import DateTimeField, Value
    from django.db.models.functions import Extract, Trunc
    from django.db.models.functions import datetime as module

    class Compiler:
        def compile(self, expression):
            return "%s", ["bound-date-marker"]

    rows = []
    safe = ("year", "iso_week_day", "custom_part", "DAY-OF-YEAR", "(day)")
    risk = ("day' OR 'x'='x", "day\n", "year; SELECT 1", "day/*x*/", "")
    for operation in ("extract", "trunc"):
        for value in (*safe, *risk):
            expression = Value(datetime(2026, 10, 27), output_field=DateTimeField())
            query = (Extract(expression, value) if operation == "extract"
                     else Trunc(expression, value, output_field=DateTimeField()))
            try:
                sql, params = query.as_sql(Compiler(), connection)
                observed = "accepted"
                bound = "bound-date-marker" in params
            except ValueError:
                observed, bound = "rejected", None
            expected = "accepted" if value in safe else "rejected"
            rows.append({"id": operation + ":" + value, "role": "safe" if value in safe else "risk",
                         "pass": observed == expected and (expected != "accepted" or bound),
                         "observed": observed, "expected": expected, "bound_value_preserved": bound})
    return rows, module.__file__


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", choices=("cookiecutter", "django"), required=True)
    parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.target.resolve()))
    rows, source = check_cookiecutter() if args.project == "cookiecutter" else check_django()
    if not Path(source).resolve().is_relative_to(args.target.resolve()):
        raise ValueError("probe imported a different project")
    print(json.dumps({"project": args.project, "source_file": str(Path(source).resolve()),
                      "rows": rows, "passed": sum(row["pass"] for row in rows), "total": len(rows)}))


if __name__ == "__main__":
    main()
