"""Non-executing boundary probes against isolated upstream Django releases."""
import argparse
from datetime import datetime
import importlib
import json
from pathlib import Path
import sys


def outcome(operation, rejection):
    try:
        value = operation()
        return {"result": "accepted", "value": str(value)[:160]}
    except rejection as exc:
        return {"result": "rejected", "exception": type(exc).__name__}


def probe_upload():
    from django.core.exceptions import SuspiciousFileOperation
    from django.core.files.storage import FileSystemStorage
    from django.utils.text import get_valid_filename

    storage = FileSystemStorage(location="unused-probe-location")
    return {
        "sanitized_empty": outcome(lambda: get_valid_filename("???"), SuspiciousFileOperation),
        "sanitized_parent": outcome(lambda: get_valid_filename("$.$.$"), SuspiciousFileOperation),
        "ordinary_filename": outcome(lambda: get_valid_filename("good file.txt"), SuspiciousFileOperation),
        "parent_traversal": outcome(lambda: storage.generate_filename("../escape.txt"), SuspiciousFileOperation),
        "ordinary_storage": outcome(lambda: storage.generate_filename("folder/good.txt"), SuspiciousFileOperation),
    }


def probe_sql():
    from django.conf import settings

    if not settings.configured:
        settings.configure(DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
                           INSTALLED_APPS=[], USE_TZ=False)
    import django
    django.setup()
    from django.db import connection
    from django.db.models import DateTimeField, Value
    from django.db.models.functions import Extract, Trunc

    class Compiler:
        def compile(self, expression):
            return "?", []

    value = Value(datetime(2024, 1, 1), output_field=DateTimeField())
    compiler = Compiler()
    invalid = "year);DROP TABLE probe;--"
    return {
        "untrusted_trunc": outcome(lambda: Trunc(value, invalid, output_field=DateTimeField()).as_sql(compiler, connection), ValueError),
        "untrusted_extract": outcome(lambda: Extract(value, invalid).as_sql(compiler, connection), ValueError),
        "ordinary_trunc": outcome(lambda: Trunc(value, "year", output_field=DateTimeField()).as_sql(compiler, connection), ValueError),
        "ordinary_extract": outcome(lambda: Extract(value, "year").as_sql(compiler, connection), ValueError),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--case", choices=["upload", "sql"], required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.target.resolve()))
    import django
    source = importlib.import_module("django.utils.text" if args.case == "upload"
                                     else "django.db.models.functions.datetime")
    print(json.dumps({"package": "Django", "version": ".".join(map(str, django.VERSION[:3])),
                      "source_file": str(Path(source.__file__).resolve()),
                      "case": args.case, "outcomes": probe_upload() if args.case == "upload" else probe_sql()},
                     sort_keys=True))


if __name__ == "__main__":
    main()
