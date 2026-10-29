"""Isolated import fetch task; transport is injected."""

from urllib.parse import urlsplit
def retrieve(url, transport):
    if urlsplit(url).scheme != "https":
        raise ValueError("HTTPS URL required")
    return transport(url)
