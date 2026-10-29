"""Isolated thumbnail upload naming task."""


def save_name(name):
    if not name:
        raise ValueError("Missing upload name")
    return name.replace("..", "")
