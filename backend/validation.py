"""
Input validation for the API.

Kept separate from main.py (and free of FastAPI imports) so it can be
tested on its own.

Two jobs:
  1. normalize_domain: turn whatever the user typed into a clean hostname,
     or reject it.
  2. assert_public_host: refuse targets that resolve to private/internal
     addresses. Without this, anyone could point the scanner at
     localhost, 192.168.x.x, or cloud metadata (169.254.169.254) and use
     your server to probe internal networks (an SSRF-style abuse).
"""

from __future__ import annotations

import ipaddress
import re
import socket

_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+[a-z]{{2,63}}$")


def normalize_domain(raw: str) -> str:
    """'https://Example.com/path?x=1' -> 'example.com'. Raises ValueError."""
    value = raw.strip().lower()
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value)  # drop scheme
    value = re.split(r"[/?#]", value, maxsplit=1)[0]     # drop path/query
    value = value.rstrip(".")

    if "@" in value or ":" in value:
        raise ValueError("Enter just a domain name (no ports or credentials).")
    if len(value) > 253 or not _DOMAIN_RE.match(value):
        raise ValueError("That doesn't look like a valid domain name.")
    return value


def assert_public_host(domain: str) -> None:
    """Raise ValueError unless every address the domain resolves to is a
    public, globally routable IP."""
    try:
        infos = socket.getaddrinfo(domain, None)
    except socket.gaierror:
        raise ValueError("Domain could not be resolved. Check the spelling.")

    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise ValueError(
                "This domain resolves to a private or reserved address "
                "and cannot be scanned."
            )
