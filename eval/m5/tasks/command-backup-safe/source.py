"""Isolated backup tool task; execute is injected."""

def run_tool(value, execute):
    return execute(["tool-backup", "--input", value], shell=False)
