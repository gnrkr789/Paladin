"""Held-out evaluation on projects that were not used to author the rules.

Expected pattern locations were fixed from a public code search before any
scanner run. They are pattern instances (an untrusted-looking variable passed
as a Mercurial checkout/update argument), not confirmed vulnerabilities.
Project code is never executed on the host; supported candidates run only in
the configured Docker runtime through the product CLI.
"""
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
# Set 1 shaped the generalized rule after its first run and is now a development
# set. Set 2 was selected and its expectations fixed before any scan with that rule.
# (directory, repository, commit, role, expected pattern instances as (path, line, note))
SUBJECTS = [
    ("hpi-swa-lab_re23-log-analysis", "hpi-swa-lab/re23-log-analysis",
     "c449e253cf1d1e217937a0f7e961d8dc6139884d", "positive",
     [("repos/mirror_repos.py", 99, 'subprocess.run(["hg", "checkout", version])')]),
    ("davidsansome_babbledrive", "davidsansome/babbledrive",
     "3c1ae1de14ac2c17bf30659d0ab00c578e02e59b", "positive",
     [("generator.py", 156, 'self.Run(["hg", "checkout", tag])')]),
    ("cyc115_juggle", "cyc115/juggle", "cb8452e0ef2f7ef2447066c76b01f78e0baa254c", "positive",
     [("src/vcs.py", 106, '_run(["hg", "update", "-r", sha])')]),
    ("managarm_xbstrap", "managarm/xbstrap", "2473efe52c471615f82f63d73733ab1c37884a5f", "positive",
     [("xbstrap/base.py", 3049, 'args = ["hg", "checkout"] extended dynamically')]),
    ("mozilla-services_updatebot", "mozilla-services/updatebot",
     "72ddfe715945b3ea4afb7b18cc5d1cf227356af4", "positive",
     [("components/hg.py", 17, 'cmdrunner.run(["hg", "update", original_revision])')]),
    ("alanhamlett_pip-update-requirements", "alanhamlett/pip-update-requirements",
     "c6dd411e2422e2d435240bc11d0273e1eb946e20", "positive",
     [("pur/packages/pip/_internal/vcs/mercurial.py", 34, 'vendored pip return ["-r", rev]')]),
    ("cwt_hg-mcp", "cwt/hg-mcp", "cd182eb2cd72c9e242e97c54ecaa20214c03d430", "negative", []),
    ("pypa_pipenv", "pypa/pipenv", "cb92306cb68992f54c2c883778159509375b917b", "negative", []),
]
SUBJECTS_2 = [
    ("mesonbuild_meson", "mesonbuild/meson", "e323ad224bc10ba24a43819a78f92b4addda6451", "positive",
     [("mesonbuild/msubprojects.py", 432, "subprocess.call(['hg', 'checkout', revno])"),
      ("mesonbuild/msubprojects.py", 434, "subprocess.check_call(['hg', 'checkout', revno])")]),
    ("siemens_kas", "siemens/kas", "055518846c3963114efbd0107bf3f2e59b4b3ba5", "positive",
     [("kas/repos.py", 920, "cmd = ['hg', 'checkout', desired_ref]")]),
    ("django_djangobench", "django/djangobench", "4c88fa81c4d7618604ae51e07c03c23f6734c2e6", "positive",
     [("djangobench/main.py", 270, "cmd = ['hg', 'update', '-C', branchname]")]),
    ("AOSC-Dev_acbs", "AOSC-Dev/acbs", "e941655324a0fa59963a677b966ff47bf723a74f", "positive",
     [("acbs/fetch.py", 269, "['hg', 'update', '-C', '-r', info.revision, '-R', location]")]),
    ("GNOME_jhbuild", "GNOME/jhbuild", "16e05af9b58b9e7433ce7417ecd8915beba59133", "positive",
     [("scripts/hg-update.py", 61, "call(['hg', 'update', '--noninteractive', '-q', parent])")]),
    ("anybox_anybox.recipe.odoo", "anybox/anybox.recipe.odoo",
     "aeab3d5fd325c7824f849a47873aa28c0c8fd191", "positive",
     [("anybox/recipe/odoo/vcs/hg.py", 207, "['hg', '--cwd', dir, 'up'] then extend(['-r', revision])")]),
    ("chrisjbillington_hg-export-tool", "chrisjbillington/hg-export-tool",
     "0138028f6ae33a726d33e3f3cd66479c4ea16bda", "positive",
     [("exporter.py", 121, "subprocess.check_call(['hg', 'up', head['hash']])")]),
    ("clarete_curdling", "clarete/curdling", "a9cce614ecd605c25dc00988d38dcf2ed9ce73ba", "positive",
     [("curdling/services/downloader.py", 382, "execute_command('hg', 'update', '-q', revision) varargs")]),
    ("ctb_pony-build", "ctb/pony-build", "e84c4c2734d8799182571339619c8f27b9a17d39", "positive",
     [("client/pony_client.py", 668, "cmdlist = ['hg', 'update', branchspec] (Python 2)")]),
    ("YosysHQ_oss-cad-suite-build", "YosysHQ/oss-cad-suite-build",
     "1925a330c27653b15beb4bd0bd1d3980d87be24c", "negative", []),
]
SETS = {"1": (ROOT / ".validation-cache" / "heldout-projects", SUBJECTS, "heldout"),
        "2": (ROOT / ".validation-cache" / "heldout2-projects", SUBJECTS_2, "heldout2")}


def tree_hash(root):
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts):
        digest.update(path.relative_to(root).as_posix().encode("utf-8") + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def cli(arguments):
    process = subprocess.run([sys.executable, "-I", "-m", "paladin.cli", "cases", *map(str, arguments), "--json"],
                             capture_output=True, text=True, encoding="utf-8", errors="replace",
                             timeout=3600, cwd=ROOT)
    return process.returncode, json.loads(process.stdout), process.stderr


def head(directory):
    return subprocess.run(["git", "-C", str(directory), "rev-parse", "HEAD"], capture_output=True,
                          text=True, check=True).stdout.strip()


def main():
    selected = sys.argv[1] if len(sys.argv) > 1 else "1"
    HELDOUT, subjects, label = SETS[selected]
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence = ROOT / "docs" / "evidence" / "private-alpha" / label / ("run-" + stamp)
    evidence.mkdir(parents=True)
    workspace = ROOT / ".validation-cache" / (label + "-eval") / ("ws-" + stamp)
    (workspace / ".paladin").mkdir(parents=True)
    shutil.copyfile(ROOT / ".paladin" / "runtime.json", workspace / ".paladin" / "runtime.json")
    rows = []
    for directory, repository, commit, role, expected in subjects:
        root = HELDOUT / directory
        if head(root) != commit:
            raise SystemExit("unexpected commit for " + repository)
        before = tree_hash(root)
        code, auto, stderr = cli(["auto", "--project", root, "--workspace", workspace])
        (evidence / (directory + ".auto.json")).write_text(json.dumps(auto, indent=2) + "\n", encoding="utf-8")
        (evidence / (directory + ".auto.stderr.txt")).write_text(stderr, encoding="utf-8")
        found = {(item["path"], item["line"]) for item in auto.get("candidates", [])}
        hits = [{"path": path, "line": line, "note": note,
                 "detected": any(path == p and abs(line - l) <= 2 for p, l in found)}
                for path, line, note in expected]
        flagged = [{"path": item["path"], "line": item["line"], "rule_id": item["rule_id"]}
                   for item in auto.get("candidates", [])
                   if not any(item["path"] == path and abs(item["line"] - line) <= 2
                              for path, line, _ in expected)]
        unsupported = [entry for entry in auto.get("unsupported_patterns", [])
                       if any(entry.startswith(path + ":") or entry.endswith(": " + path)
                              for path, _, _ in expected)]
        rows.append({
            "subject": repository, "commit": commit, "role": role, "scan_status": auto.get("status"),
            "expected_instances": hits,
            "unsupported_reported_at_expected_files": unsupported,
            "candidates": auto.get("candidates", []),
            "unexpected_candidates": flagged,
            "case_runs": [{key: run.get(key) for key in ("status", "reason", "checks", "evidence_sha256")}
                          | {"path": run.get("candidate", {}).get("path")}
                          for run in auto.get("case_runs", [])],
            "unsupported_pattern_count": len(auto.get("unsupported_patterns", [])),
            "source_unchanged": tree_hash(root) == before, "source_tree_sha256": before})
    expected_total = sum(len(row["expected_instances"]) for row in rows)
    detected_total = sum(item["detected"] for row in rows for item in row["expected_instances"])
    negatives_clean = all(not row["candidates"] for row in rows if row["role"] == "negative")
    _, listed, _ = cli(["list", "--workspace", workspace])
    report = {"set": selected, "runtime": json.loads((ROOT / ".paladin" / "runtime.json").read_text()),
              "unexpected_candidates": sum(len(row["unexpected_candidates"]) for row in rows),
              "workspace": str(workspace), "subjects": rows,
              "expected_instances": expected_total, "detected_instances": detected_total,
              "negative_controls_without_candidates": negatives_clean,
              "promoted_cases": listed.get("cases", []),
              "sources_unchanged": all(row["source_unchanged"] for row in rows)}
    (evidence / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"evidence": str(evidence), "detected": detected_total, "expected": expected_total,
                      "negatives_clean": negatives_clean, "promoted": len(report["promoted_cases"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
