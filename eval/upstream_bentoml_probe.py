"""Probe BentoML's actual HTTP boundary without deserializing a request."""
import argparse
import asyncio
from importlib.metadata import version
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch


class ReachedSerde(Exception):
    """The request passed the media-type guard and reached dispatch."""


class TrapSerde(dict):
    def __getitem__(self, media_type):
        raise ReachedSerde(media_type)


async def probe(factory, media_type, is_main, BentoMLException):
    dummy = SimpleNamespace(is_main=is_main,
                            service=SimpleNamespace(apis={"probe": object()}, context=None),
                            _service_instance=SimpleNamespace(probe=lambda: None))
    request = SimpleNamespace(headers={"Content-Type": media_type})
    try:
        await factory.api_endpoint(dummy, "probe", request)
    except ReachedSerde as exc:
        return {"result": "reached_serde", "media_type": str(exc)}
    except BentoMLException as exc:
        return {"result": "rejected_before_serde", "exception": type(exc).__name__,
                "error_code": exc.error_code}
    return {"result": "unexpected_completion"}


async def run(factory):
    from _bentoml_impl import serde
    from bentoml.exceptions import BentoMLException

    with patch.object(serde, "ALL_SERDE", TrapSerde()):
        return {
            "main_pickle": await probe(factory, "application/vnd.bentoml+pickle", True, BentoMLException),
            "main_json": await probe(factory, "application/json", True, BentoMLException),
            "internal_pickle": await probe(factory, "application/vnd.bentoml+pickle", False, BentoMLException),
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--compat", type=Path, required=True)
    args = parser.parse_args()
    sys.path[:0] = [str(args.compat.resolve()), str(args.target.resolve())]
    from _bentoml_impl.server.app import ServiceAppFactory

    print(json.dumps({"package": "bentoml", "version": version("bentoml"),
                      "source_file": str(Path(sys.modules[ServiceAppFactory.__module__].__file__).resolve()),
                      "outcomes": asyncio.run(run(ServiceAppFactory))}, sort_keys=True))


if __name__ == "__main__":
    main()
