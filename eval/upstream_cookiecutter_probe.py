"""Record real Cookiecutter argv construction without invoking a VCS."""
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
    from importlib.metadata import version
    from cookiecutter import vcs

    cases = {}
    with tempfile.TemporaryDirectory() as directory:
        for repo_type, checkout in [("hg", "--config=harmless"), ("hg", "stable"), ("git", "stable")]:
            calls = []

            def capture(argv, **kwargs):
                calls.append(list(argv))
                return b""

            with patch.object(vcs, "is_vcs_installed", return_value=True), \
                    patch.object(vcs.subprocess, "check_output", side_effect=capture):
                vcs.clone(repo_type + "+https://example.invalid/demo", checkout=checkout,
                          clone_to_dir=directory, no_input=True)
            cases[repo_type + ":" + checkout] = calls
    print(json.dumps({"package": "cookiecutter", "version": version("cookiecutter"),
                      "source_file": str(Path(vcs.__file__).resolve()),
                      "outcomes": cases}, sort_keys=True))


if __name__ == "__main__":
    main()
