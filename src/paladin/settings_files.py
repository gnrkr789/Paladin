"""Project settings files written by Paladin's installers: link checks and atomic replacement.

Shared by the hook and MCP installers so the security-relevant path checks exist once.
"""
import os
from pathlib import Path
import stat
import tempfile


def linked(path):
    """True for a symlink or a Windows reparse point (junction)."""
    info = os.lstat(path)
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def safe_file(workspace, relative):
    """A settings file inside an existing workspace; its folder is created, links are refused."""
    workspace = Path(workspace)
    if not workspace.is_dir() or linked(workspace):
        raise ValueError("invalid_workspace")
    path = workspace / relative
    directory = path.parent
    if os.path.lexists(directory) and (linked(directory) or not directory.is_dir()):
        raise ValueError("unsafe_settings_directory")
    directory.mkdir(exist_ok=True)
    if not directory.resolve().is_relative_to(workspace.resolve()):
        raise ValueError("unsafe_settings_directory")
    if os.path.lexists(path) and (linked(path) or not path.is_file()):
        raise ValueError("unsafe_settings_file")
    return path


def replace_text(path, text):
    """Write through a temporary file in the same folder, then rename over the target."""
    descriptor, temporary = tempfile.mkstemp(prefix="settings-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
