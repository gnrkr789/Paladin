"""The per-user Paladin home: search state shared by every project on this machine.

It holds what `paladin setup` and `model prepare` create (Milvus configuration, the encoder,
the pattern index, verified cases). Projects keep only their own hook and MCP entries.
"""
import os
from pathlib import Path
import sys

VARIABLE = "PALADIN_HOME"


def default_home():
    """PALADIN_HOME, else the platform's per-user data folder plus paladin."""
    if os.environ.get(VARIABLE):
        return Path(os.environ[VARIABLE])
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    else:
        base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "paladin"
