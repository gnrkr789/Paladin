"""Isolated media tool task; execute is injected."""

def run_tool(value, execute):
    return execute("tool-media --input " + value, shell=True)
