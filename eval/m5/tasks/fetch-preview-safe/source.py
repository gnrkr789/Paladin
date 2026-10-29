"""Isolated preview fetch task; transport is injected."""

from urllib.parse import urlsplit
import ipaddress


def retrieve(url, transport):
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("HTTPS URL required")
    try:
        address = ipaddress.ip_address(parts.hostname)
    except ValueError:
        if parts.hostname != "preview.example.test":
            raise ValueError("Host not allowed")
    else:
        if not address.is_global:
            raise ValueError("Private address not allowed")
    return transport(url)
