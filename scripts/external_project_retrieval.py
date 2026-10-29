"""Observe code-derived reference retrieval; this is not source scanning."""
import asyncio
from scripts.external_project_comparison import EVIDENCE, ROOT, save
from paladin.mcp_server import WorkerRunner


async def main():
    runner = WorkerRunner(ROOT, timeout=90)
    queries = {
        "cookiecutter": "Python repository template loader forwards a caller-supplied checkout revision to subprocess argv for Mercurial and Git without separating options.",
        "django": "Python ORM date functions interpolate user-controlled date-part identifiers into SQL templates while data values are parameterized.",
    }
    rows = {}
    for project, query in queries.items():
        result = await runner.call("search_prevention_patterns", {"intent": query, "limit": 5})
        rows[project] = {"query": query, "result": result}
        print(project, result["status"], [item["pattern"]["pattern_id"] for item in result.get("matches", [])])
    rows["check_changes"] = await runner.call("check_changes", {})
    save(EVIDENCE / "retrieval-observation.json", {"kind": "manual_code_intent_retrieval_not_automatic_detection", "rows": rows})


if __name__ == "__main__":
    asyncio.run(main())
