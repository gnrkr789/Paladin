"""Post hoc ASGI boundary check for the isolated BentoML agent repairs."""

import argparse
import functools
import json
import logging
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--compat", type=Path, required=True)
    parser.add_argument("--cases", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.target.resolve()))
    sys.path.insert(0, str(args.compat.resolve()))

    from _bentoml_impl import serde
    from _bentoml_impl.server.app import ServiceAppFactory
    from bentoml._internal.server.base_app import BaseAppFactory
    from starlette.applications import Starlette
    from starlette.routing import Route
    from starlette.testclient import TestClient

    cases = [case for case in json.loads(args.cases.read_text(encoding="ascii"))["cases"]
             if case["family"] == "unsafe_deserialization"]
    outcomes = {}
    observed = []
    logging.disable(logging.CRITICAL)

    class ReachedSerde(Exception):
        pass

    class TrapSerde(dict):
        def __getitem__(self, media_type):
            observed.append(media_type)
            raise ReachedSerde(media_type)

    with patch.object(serde, "ALL_SERDE", TrapSerde()):
        for case in cases:
            factory = object.__new__(ServiceAppFactory)
            factory.service = SimpleNamespace(
                name="probe", apis={"probe": object()}, context=None, mount_apps=[])
            factory._service_instance = SimpleNamespace(probe=lambda: None)
            base_app = Starlette(routes=[Route(
                "/probe", functools.partial(factory.api_endpoint, "probe"),
                methods=["POST"])])
            with patch.object(BaseAppFactory, "__call__", return_value=base_app):
                app = factory(is_main=case["entrypoint"] == "main_http")
            observed.clear()
            with TestClient(app, raise_server_exceptions=False) as client:
                response = client.post(
                    "/probe", headers={"Content-Type": case["input"]}, content=b"{}")
            if observed:
                result = "reached_serde"
            elif response.status_code == 415:
                result = "rejected_before_serde"
            else:
                result = "unexpected_response"
            outcomes[case["id"]] = {
                "result": result, "status_code": response.status_code,
                "serde_media_types": list(observed),
            }

    from _bentoml_impl.server import app as app_module
    print(json.dumps({"source_file": str(Path(app_module.__file__).resolve()),
                      "outcomes": outcomes}, sort_keys=True))


if __name__ == "__main__":
    main()
