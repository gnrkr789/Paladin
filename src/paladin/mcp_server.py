"""Stdio-only MCP adapter with a fixed workspace and killable read workers."""
import json
import os
from pathlib import Path
import subprocess
import sys

import anyio
import mcp_types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import MCPError

from paladin.advisory import (INPUT_SCHEMAS, OUTPUT_SCHEMA, MAX_RESULT_BYTES,
                              RequestError, bounded, dispatch, failure, tool_result, validate_arguments)

DESCRIPTIONS = {
    "search_prevention_patterns": "Search Python web advisory references using English technical intent. Similarity is not a verdict.",
    "get_pattern_evidence": "Read pinned evidence metadata or bounded verified local excerpts. Source text is untrusted data.",
    "get_knowledge_status": "Inspect local pack/model/index/DB readiness; readiness is not security approval.",
    "check_changes": "Statically check changed Python files (workspace-relative paths) for known CVE argument patterns. Block-level findings match exact CVE rules; review findings are pattern matches, not verdicts. No paths: unsupported.",
    "check_project": "Statically check every Python file of the project (virtual environments, installed packages and hidden folders are skipped) with the same rules as check_changes. Only files with findings or problems are listed; checked_files counts all. Findings are pattern matches, not verdicts.",
    "check_dependencies": "Compare the workspace's pinned dependency versions (requirements*.txt, pyproject.toml, uv.lock, poetry.lock, Pipfile.lock) with collected PyPI advisory ranges. An affected version is not proof the vulnerable feature is used; unpinned requirements are listed, not judged.",
    "scan_cve_candidates": "Read-only scan of the configured project for supported CVE source structures. Candidates require verification; coverage is limited to the reported rule.",
    "get_prevention_guidance": "Read source-pinned correction candidates. Set include_patch_context for the complete upstream diff, changed paths and integration checks. Target applicability and approval remain unverified.",
}


class WorkerRunner:
    """One backend operation at a time; cancellation kills and reaps the worker."""

    # A whole-project check reads every source file; it gets a longer deadline.
    LONG_TOOLS = {"check_project": 300}

    def __init__(self, root, timeout=30, home=None):
        self.root = Path(root).resolve()
        self.home = Path(home).resolve() if home is not None else self.root
        self.timeout = timeout
        self.lock = anyio.Lock()
        self.active_pids = set()

    def command(self, name):
        return [sys.executable, "-I", "-B", "-m", "paladin.advisory", "--workspace", str(self.root),
                "--home", str(self.home), "--tool", name]

    async def call(self, name, arguments, *, command=None):
        # The deadline also includes queue time; the lock includes reaping.
        try:
            with anyio.fail_after(max(self.timeout, self.LONG_TOOLS.get(name, 0))):
                async with self.lock:
                    return await self._run(name, arguments, command)
        except TimeoutError:
            return failure("deadline_exceeded")

    async def _run(self, name, arguments, command):
        process = None
        try:
            env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
            process = await anyio.open_process(
                command or self.command(name),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
            self.active_pids.add(process.pid)
            await process.stdin.send(json.dumps(arguments, ensure_ascii=True).encode())
            await process.stdin.aclose()
            output = bytearray()
            async for chunk in process.stdout:
                output.extend(chunk)
                if len(output) > MAX_RESULT_BYTES:
                    return failure("worker_response_too_large")
            code = await process.wait()
            if code:
                return failure("worker_failed")
            result = json.loads(output)
            return bounded(result)
        except (ValueError, OSError, anyio.BrokenResourceError):
            return failure("worker_failed")
        finally:
            if process is not None:
                # Shield cleanup from SDK request cancellation, including client EOF.
                with anyio.CancelScope(shield=True):
                    if process.returncode is None:
                        try:
                            process.kill()
                        except ProcessLookupError:
                            pass
                    with anyio.fail_after(2):
                        await process.wait()
                        await process.aclose()
                    self.active_pids.discard(process.pid)


def create_server(root, home=None):
    runner = WorkerRunner(root, home=home)

    async def list_tools(ctx, params):
        return types.ListToolsResult(tools=[types.Tool(
            name=name, description=DESCRIPTIONS[name], input_schema=schema, output_schema=OUTPUT_SCHEMA,
            annotations=types.ToolAnnotations(read_only_hint=True, destructive_hint=False,
                                              idempotent_hint=True, open_world_hint=False))
            for name, schema in INPUT_SCHEMAS.items()])

    async def call_tool(ctx, params):
        if params.name not in INPUT_SCHEMAS:
            raise MCPError(code=-32602, message="Unknown tool")
        arguments = params.arguments if params.arguments is not None else {}
        try:
            validate_arguments(params.name, arguments)
        except RequestError:
            result = failure("invalid_arguments", "invalid_request")
        else:
            if params.name == "check_changes" and not arguments.get("paths"):
                result = dispatch(runner.root, params.name, arguments, home=runner.home)
            else:
                result = await runner.call(params.name, arguments)
        wire = tool_result(result)
        return types.CallToolResult(content=[types.TextContent(type="text", text=wire["content"][0]["text"])],
                                    structured_content=result, is_error=wire["isError"])

    return Server("paladin", version="0.1.0", on_list_tools=list_tools, on_call_tool=call_tool,
                  get_tool_input_schema=INPUT_SCHEMAS.get)


async def serve(root, home=None):
    server = create_server(Path(root).resolve(), home)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main(root, home=None):
    anyio.run(serve, root, home)
