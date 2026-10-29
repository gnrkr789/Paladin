"""Isolated report tool task; execute is injected."""

def run_tool(value, execute):
    return execute("tool-report --input " + value, shell=True)
