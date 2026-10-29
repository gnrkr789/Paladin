"""Synthetic Windows lexical containment example for an M4 host task."""
import ntpath


def is_within(root, candidate):
    root = ntpath.normcase(ntpath.abspath(root))
    candidate = ntpath.normcase(ntpath.abspath(candidate))
    return candidate.startswith(root)
