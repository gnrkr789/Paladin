"""Record an independent ASGI sensitivity check without changing primary scores."""

import hashlib
import argparse
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".validation-cache"
CASES = ROOT / "eval/guidance_agent_cases.json"
PROBE = ROOT / "eval/bentoml_asgi_posthoc_probe.py"
OUTPUT = ROOT / "docs/evidence/guidance-agent-worker-eval/posthoc-bentoml-asgi.json"
PYTHON = Path("C:/Users/user/AppData/Roaming/uv/python/cpython-3.11-windows-x86_64-none/python.exe")
COMPAT = CACHE / "upstream/legacy-bento-deps"
SOURCE = "_bentoml_impl/server/app.py"
TARGETS = {
    "vulnerable_control": CACHE / "upstream/bentoml-1.2.4",
    "A": CACHE / "agent-worker-eval/oracles/A-unsafe_deserialization",
    "C": CACHE / "agent-worker-eval/oracles/C-unsafe_deserialization",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_patch_identity(report):
    for arm in ("A", "C"):
        key = arm + "-unsafe_deserialization"
        run_file = OUTPUT.parent / "runs" / key / "run.json"
        run = json.loads(run_file.read_text(encoding="ascii"))
        expected = run["after_sha256"][SOURCE]
        archived = OUTPUT.parent / "runs" / key / "source.after" / SOURCE
        actual = report["results"][arm]["source_sha256"]
        if actual != expected or digest(archived) != expected:
            raise ValueError("post hoc source differs from scored repair: " + key)
        if digest(TARGETS[arm] / SOURCE) != expected:
            raise ValueError("oracle source differs from scored repair: " + key)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.verify:
        report = json.loads(OUTPUT.read_text(encoding="ascii"))
        if report["cases_sha256"] != digest(CASES) or report["probe_sha256"] != digest(PROBE):
            raise ValueError("post hoc input identity changed")
        verify_patch_identity(report)
        print("POSTHOC_IDENTITY_OK")
        return
    if OUTPUT.exists():
        raise FileExistsError(OUTPUT)
    cases = [item for item in json.loads(CASES.read_text(encoding="ascii"))["cases"]
             if item["family"] == "unsafe_deserialization"]
    results = {}
    for arm, target in TARGETS.items():
        command = [str(PYTHON), "-B", str(PROBE), "--target", str(target),
                   "--compat", str(COMPAT), "--cases", str(CASES)]
        run = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                             timeout=90, check=True)
        output = json.loads(run.stdout)
        source = (target / SOURCE).resolve()
        if Path(output["source_file"]).resolve() != source:
            raise ValueError("probe loaded the wrong source")
        assessments = []
        for case in cases:
            expected = case["vulnerable" if arm == "vulnerable_control" else "fixed"]
            observed = output["outcomes"][case["id"]]
            passed = observed["result"] == expected
            if expected == "rejected_before_serde":
                passed = passed and observed["status_code"] == 415
            assessments.append({"id": case["id"], "expected": expected,
                                "observed": observed, "pass": passed})
        results[arm] = {"source_file": str(source), "source_sha256": digest(source),
                        "assessments": assessments,
                        "passed": sum(item["pass"] for item in assessments),
                        "total": len(assessments)}
    report = {"kind": "posthoc_asgi_sensitivity_check", "cases_sha256": digest(CASES),
              "probe_sha256": digest(PROBE), "results": results,
              "limits": [
                  "Primary frozen oracle outcomes and scores remain unchanged.",
                  "A synthetic Starlette route and mocked BaseAppFactory initialization are used.",
                  "The real ServiceAppFactory.__call__ and api_endpoint execute over ASGI.",
                  "The serde lookup is trapped; no pickle payload is loaded.",
                  "This checks four boundary cases, not a deployed BentoML service.",
              ]}
    verify_patch_identity(report)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("x", encoding="ascii", newline="\n") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=True, sort_keys=True)
        stream.write("\n")
    print(json.dumps({key: {"passed": value["passed"], "total": value["total"]}
                      for key, value in results.items()}, sort_keys=True))


if __name__ == "__main__":
    main()
