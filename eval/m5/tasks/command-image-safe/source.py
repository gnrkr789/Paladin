"""Isolated image tool task; execute is injected."""

def run_tool(value, execute):
    return execute(["tool-image", "--input", value], shell=False)
