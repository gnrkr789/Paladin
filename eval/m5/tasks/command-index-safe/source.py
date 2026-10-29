"""Isolated index tool task; execute is injected."""

def run_tool(value, execute):
    return execute(["tool-index", "--input", value], shell=False)
