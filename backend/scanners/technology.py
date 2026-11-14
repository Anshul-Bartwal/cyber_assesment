"""
Basic technology detection.

Covers spec section 9. Deliberately shallow for the MVP - header-based
fingerprinting only, no aggressive probing or version brute-forcing.
This is informational (Category.TECHNOLOGY, severity INFO); it's a
building block for the future CVE-correlation feature (section 10),
not a vulnerability check on its own.
"""

from __future__ import annotations

import requests

from models.finding import (
    Finding, Severity, FindingStatus, Category, make_pass, make_error,
)

TIMEOUT = 8

# Simple signature -> label mapping. Deliberately small and conservative;
# false positives are worse than a shorter list here.
_SERVER_SIGNATURES = {
    "nginx": "nginx",
    "apache": "Apache",
    "cloudflare": "Cloudflare",
    "microsoft-iis": "Microsoft IIS",
}

_GENERATOR_SIGNATURES = {
    "wordpress": "WordPress",
    "wix": "Wix",
    "shopify": "Shopify",
    "squarespace": "Squarespace",
}


def scan_technology(domain: str) -> list[Finding]:
    url = f"https://{domain}"
    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
    except requests.exceptions.RequestException as exc:
        return [make_error(
            "technology", "Technology Detection", Category.TECHNOLOGY,
            f"Could not fetch {url}: {exc}",
        )]

    headers = {k.lower(): v for k, v in resp.headers.items()}
    detected: dict[str, str] = {}

    server_header = headers.get("server", "").lower()
    for signature, label in _SERVER_SIGNATURES.items():
        if signature in server_header:
            detected["web_server"] = label
            break

    powered_by = headers.get("x-powered-by", "")
    if powered_by:
        detected["x_powered_by"] = powered_by

    body_snippet = resp.text[:20000].lower() if resp.text else ""
    for signature, label in _GENERATOR_SIGNATURES.items():
        if signature in body_snippet:
            detected["platform"] = label
            break

    if not detected:
        return [make_pass(
            "technology", "Technology Detection", Category.TECHNOLOGY,
            "No specific technology signatures were confidently identified "
            "from response headers or page content.",
        )]

    summary = ", ".join(f"{k.replace('_', ' ')}: {v}" for k, v in detected.items())
    return [Finding(
        id="technology",
        title="Detected technologies",
        category=Category.TECHNOLOGY,
        severity=Severity.INFO,
        status=FindingStatus.PASS,
        description=f"Detected: {summary}.",
        recommendation=(
            "Keep detected platforms and server software up to date. "
            "Future versions of this scanner may correlate detected "
            "versions with known CVEs."
        ),
        evidence=detected,
    )]


def run(domain: str) -> list[Finding]:
    return scan_technology(domain)
