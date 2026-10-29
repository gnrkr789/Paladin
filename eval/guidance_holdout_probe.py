"""Execute held-out boundary inputs on real upstream package code."""
import argparse
import asyncio
from datetime import datetime
from importlib.metadata import version
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch


def accepted_or_rejected(operation, rejection):
    try:
        value = operation()
        return {"result": "accepted", "value": str(value)[:160]}
    except rejection as exc:
        return {"result": "rejected", "exception": type(exc).__name__}


def django_upload(cases):
    from django.core.exceptions import SuspiciousFileOperation
    from django.core.files.storage import FileSystemStorage
    from django.utils.text import get_valid_filename

    storage = FileSystemStorage(location="unused-holdout-location")
    outcomes = {}
    for case in cases:
        operation = (lambda value=case["input"]: get_valid_filename(value)) if case["entrypoint"] == "valid_filename" \
            else (lambda value=case["input"]: storage.generate_filename(value))
        outcomes[case["id"]] = accepted_or_rejected(operation, SuspiciousFileOperation)
    return outcomes


def django_sql(cases):
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

    value = Value(datetime(2024, 2, 3), output_field=DateTimeField())
    compiler = Compiler()
    outcomes = {}
    for case in cases:
        if case["entrypoint"] == "trunc":
            operation = lambda kind=case["input"]: Trunc(value, kind, output_field=DateTimeField()).as_sql(compiler, connection)
        else:
            operation = lambda lookup=case["input"]: Extract(value, lookup).as_sql(compiler, connection)
        outcomes[case["id"]] = accepted_or_rejected(operation, ValueError)
    return outcomes


def cpython_url(cases):
    from urllib.parse import urlsplit

    outcomes = {}
    for case in cases:
        result = accepted_or_rejected(lambda url=case["input"]: urlsplit(url).hostname, ValueError)
        outcomes[case["id"]] = result
    return outcomes


def cookiecutter_checkout(cases):
    from cookiecutter import vcs

    outcomes = {}
    with tempfile.TemporaryDirectory() as directory:
        for case in cases:
            calls = []

            def capture(argv, **kwargs):
                calls.append(list(argv))
                return b""

            with patch.object(vcs, "is_vcs_installed", return_value=True), \
                    patch.object(vcs.subprocess, "check_output", side_effect=capture):
                vcs.clone("hg+https://example.invalid/new", checkout=case["input"],
                          clone_to_dir=directory, no_input=True)
            argv = calls[1]
            if argv == ["hg", "checkout", case["input"]]:
                result = "option_exposed" if case["input"].startswith("-") else "ordinary_argv"
            elif argv == ["hg", "checkout", "--", case["input"]]:
                result = "literal_after_terminator" if case["input"].startswith("-") else "ordinary_argv_with_terminator"
            else:
                result = "unexpected_argv"
            outcomes[case["id"]] = {"result": result, "argv": argv}
    return outcomes


class ReachedSerde(Exception):
    pass


class TrapSerde(dict):
    def __getitem__(self, media_type):
        raise ReachedSerde(media_type)


async def bentoml_http(cases):
    from _bentoml_impl.server.app import ServiceAppFactory
    from _bentoml_impl import serde
    from bentoml.exceptions import BentoMLException

    outcomes = {}
    with patch.object(serde, "ALL_SERDE", TrapSerde()):
        for case in cases:
            dummy = SimpleNamespace(is_main=case["entrypoint"] == "main_http",
                                    service=SimpleNamespace(apis={"probe": object()}, context=None),
                                    _service_instance=SimpleNamespace(probe=lambda: None))
            request = SimpleNamespace(headers={"Content-Type": case["input"]})
            try:
                await ServiceAppFactory.api_endpoint(dummy, "probe", request)
                outcome = {"result": "unexpected_completion"}
            except ReachedSerde as exc:
                outcome = {"result": "reached_serde", "media_type": str(exc)}
            except BentoMLException as exc:
                outcome = {"result": "rejected_before_serde", "exception": type(exc).__name__,
                           "error_code": exc.error_code}
            outcomes[case["id"]] = outcome
    return outcomes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--family", required=True)
    parser.add_argument("--target", type=Path)
    parser.add_argument("--compat", type=Path)
    args = parser.parse_args()
    if args.target:
        sys.path.insert(0, str(args.target.resolve()))
    if args.compat:
        sys.path.insert(0, str(args.compat.resolve()))
    cases = [case for case in json.loads(args.cases.read_text(encoding="ascii"))["cases"]
             if case["family"] == args.family]
    if args.family == "path_traversal":
        outcomes = django_upload(cases)
    elif args.family == "sql_injection":
        outcomes = django_sql(cases)
    elif args.family == "ssrf":
        outcomes = cpython_url(cases)
    elif args.family == "command_injection":
        outcomes = cookiecutter_checkout(cases)
    elif args.family == "unsafe_deserialization":
        outcomes = asyncio.run(bentoml_http(cases))
    else:
        raise ValueError("unsupported holdout family")
    if args.family in ("path_traversal", "sql_injection"):
        import importlib
        import django
        package = "Django"
        source = importlib.import_module("django.utils.text" if args.family == "path_traversal"
                                         else "django.db.models.functions.datetime").__file__
        observed_version = ".".join(map(str, django.VERSION[:3]))
    elif args.family == "ssrf":
        import urllib.parse
        package = "CPython"
        source = urllib.parse.__file__
        observed_version = sys.version.split()[0]
    elif args.family == "command_injection":
        from cookiecutter import vcs
        package = "cookiecutter"
        source = vcs.__file__
        observed_version = version(package)
    else:
        from _bentoml_impl.server import app
        package = "bentoml"
        source = app.__file__
        observed_version = version(package)
    print(json.dumps({"family": args.family, "package": package, "version": observed_version,
                      "source_file": str(Path(source).resolve()), "python": sys.version.split()[0],
                      "outcomes": outcomes}, sort_keys=True))


if __name__ == "__main__":
    main()
