"""Compare actual urllib.parse bracketed-host behavior without network access."""
import json
from pathlib import Path
import sys
import urllib.parse
from urllib.parse import urlsplit


def outcome(url):
    try:
        parsed = urlsplit(url)
        return {"result": "accepted", "hostname": parsed.hostname}
    except ValueError:
        return {"result": "rejected", "exception": "ValueError"}


def main():
    cases = {
        "bracketed_ipv4": "https://[127.0.0.1]/path",
        "invalid_bracketed_host": "https://[not-ipv6]/path",
        "valid_ipv6": "https://[::1]/path",
        "valid_ipvfuture": "https://[v6a.ip]/path",
    }
    print(json.dumps({"package": "CPython", "version": sys.version.split()[0],
                      "source_file": str(Path(urllib.parse.__file__).resolve()),
                      "outcomes": {key: outcome(value) for key, value in cases.items()}}, sort_keys=True))


if __name__ == "__main__":
    main()
