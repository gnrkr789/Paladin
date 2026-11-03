"""The per-user Paladin home: search state shared by every project on this machine.

It holds what `paladin setup` and `model prepare` create (Milvus configuration, the encoder,
the pattern index, verified cases). Projects keep only their own hook and MCP entries.
"""
import os
from pathlib import Path
import sys

VARIABLE = "PALADIN_HOME"


def default_home():
    """PALADIN_HOME, else ~/.paladin on Windows, else the XDG data folder plus paladin.

    Windows avoids %LOCALAPPDATA%: MSIX-packaged agent hosts (the Claude and Codex desktop
    apps) see a private, redirected copy of it, so a terminal and a desktop agent would use
    different homes, and Docker would mount yet another path.
    """
    if os.environ.get(VARIABLE):
        return Path(os.environ[VARIABLE])
    if sys.platform == "win32":
        return Path.home() / ".paladin"
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "paladin"
