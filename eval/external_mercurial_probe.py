"""Post-primary local Mercurial compatibility probe, without remote access."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
HG = ROOT / ".validation-cache/external-comparison/hg-runtime"
PYTHON = ROOT / ".validation-cache/external-comparison/venv/Scripts/python.exe"
CODE = "import sys;sys.path.insert(0," + repr(str(HG)) + ");from mercurial import dispatch;dispatch.run()"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.target.resolve()))
    from cookiecutter import vcs
    original = subprocess.check_output
    environment = {key: value for key, value in os.environ.items()
                   if key.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP"}}
    environment.update(HGPLAIN="1", HGRCPATH="", HGUSER="Local Evaluation <test@example.invalid>")

    def hg(values, cwd):
        return original([str(PYTHON), "-B", "-c", CODE, *values], cwd=cwd,
                        env=environment, stderr=subprocess.STDOUT)

    rows = []
    with tempfile.TemporaryDirectory() as folder:
        base = Path(folder)
        source = base / "source"
        source.mkdir()
        hg(["init"], source)
        (source / "file.txt").write_text("local fixture\n", encoding="ascii")
        hg(["add", "file.txt"], source)
        hg(["commit", "-m", "initial"], source)
        hg(["branch", "--", "--literal-branch"], source)
        (source / "file.txt").write_text("branch fixture\n", encoding="ascii")
        hg(["commit", "-m", "named branch"], source)

        def real_hg(argv, **kwargs):
            if argv[0] != "hg":
                raise ValueError("unexpected subprocess")
            return hg(argv[1:], kwargs["cwd"])

        for number, checkout in enumerate(("default", "--literal-branch")):
            try:
                with patch.object(vcs, "is_vcs_installed", return_value=True), \
                        patch.object(vcs.subprocess, "check_output", side_effect=real_hg):
                    destination = vcs.clone("hg+" + str(source), checkout=checkout,
                                            clone_to_dir=str(base / str(number)), no_input=True)
                branch = hg(["branch"], destination).decode().strip()
                rows.append({"checkout": checkout, "pass": branch == checkout, "branch": branch})
            except Exception as error:
                rows.append({"checkout": checkout, "pass": False,
                             "error": type(error).__name__, "detail": str(error)})
    print(json.dumps({"source_file": str(Path(vcs.__file__).resolve()), "rows": rows,
                      "passed": sum(row["pass"] for row in rows), "total": len(rows)}))


if __name__ == "__main__":
    main()
