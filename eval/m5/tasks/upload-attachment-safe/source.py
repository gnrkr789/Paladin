"""Isolated attachment upload naming task."""


def save_name(name):
    if not name or name in (".", "..") or "/" in name or "\\" in name:
        raise ValueError("Unsafe upload name")
    return name
