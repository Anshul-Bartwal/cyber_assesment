"""
Web scanner: HTTPS enforcement, security headers, cookie flags.

Covers spec sections 5.1 (HTTPS), 5.2 (Security Headers), 5.3 (Cookies).

Every public function here returns list[Finding]. No scoring or severity
weighting decisions beyond an initial, well-established default belong
in this file - that's the risk engine's job (Phase 3).
"""

from __future__ import annotations

import requests

from backend.models.finding import (
    Finding, Severity, Effort, Category, FindingStatus, make_pass, make_error,
)
TIMEOUT = 8
def scan_https_redirect(domain: str) -> list[Finding]:
    """Does http://domain redirect to https://domain?

    Concept: a business site that is reachable over plain HTTP without
    being redirected to HTTPS may transmit data (including login forms)
    unencrypted if a user happens to type the http:// version.
    """
    http_url = f"http://{domain}"
    try:
        resp = requests.get(http_url, timeout=TIMEOUT, allow_redirects=True)
    except requests.exceptions.SSLError:
        return [make_error(
            "https_redirect", "HTTPS Redirect", Category.WEB_SECURITY,
            "TLS error while following redirects.",
        )]
    except requests.exceptions.ConnectionError:
        # Port 80 might simply be closed - some sites disable HTTP entirely,
        # which is actually fine from a security standpoint.
        return [make_pass(
            "https_redirect", "HTTPS Redirect", Category.WEB_SECURITY,
            "Port 80 is not reachable (HTTP appears disabled entirely).",
        )]
    except requests.exceptions.RequestException as exc:
        return [make_error(
            "https_redirect", "HTTPS Redirect", Category.WEB_SECURITY, str(exc),
        )]

    final_url = resp.url
    if final_url.startswith("https://"):
        return [make_pass(
            "https_redirect", "HTTPS Redirect", Category.WEB_SECURITY,
            f"http://{domain} redirects to {final_url}",
        )]

    return [Finding(
        id="https_redirect",
        title="Website does not enforce HTTPS",
        category=Category.WEB_SECURITY,
        severity=Severity.HIGH,
        status=FindingStatus.ISSUE,
        description=(
            f"http://{domain} remained accessible over plain HTTP "
            f"instead of redirecting to HTTPS (final URL: {resp.url})."
        ),
        business_impact=(
            "Visitors who type or click an http:// link may send data, "
            "including form submissions, over an unencrypted connection "
            "that can be intercepted or tampered with on the network."
        ),
        recommendation=(
            "Configure the web server or load balancer to redirect all "
            "HTTP traffic to HTTPS (a 301 redirect)."
        ),
        effort=Effort.LOW,
        evidence={"final_url": resp.url},
    )]

## headers
_HEADER_CHECKS = [ #id,title,desc,recommendation,severity
    (
        "hsts", "Strict-Transport-Security",
        "HSTS tells browsers to only ever connect to this site over "
        "HTTPS, even if a user types an http:// address, preventing "
        "downgrade attacks.",
        "Add a Strict-Transport-Security header, e.g. "
        "'max-age=31536000; includeSubDomains'.",
        Severity.MEDIUM,
    ),
    (
        "csp", "Content-Security-Policy",
        "CSP restricts which sources of scripts, styles, and other "
        "content the browser will load, reducing the impact of "
        "cross-site scripting (XSS) if it occurs.",
        "Define a Content-Security-Policy appropriate to the site's "
        "actual script/style sources, starting permissive and tightening.",
        Severity.MEDIUM,
    ),
    (
        "x_frame_options", "X-Frame-Options",
        "This header prevents the site from being loaded inside an "
        "iframe on another site, which helps prevent clickjacking.",
        "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN', or an equivalent "
        "frame-ancestors directive in CSP.",
        Severity.LOW,
    ),
    (
        "x_content_type_options", "X-Content-Type-Options",
        "This header stops the browser from guessing content types, "
        "which can prevent certain script-injection attacks via "
        "mislabeled file uploads.",
        "Add 'X-Content-Type-Options: nosniff'.",
        Severity.LOW,
    ),
    (
        "referrer_policy", "Referrer-Policy",
        "This header controls how much of the current page's URL is "
        "sent to other sites via the Referer header when users click "
        "outbound links.",
        "Add a 'Referrer-Policy' header, e.g. "
        "'strict-origin-when-cross-origin'.",
        Severity.LOW,
    ),
]


def scan_security_headers(domain: str) -> list[Finding]:
    https_url = f"https://{domain}"

    try:
        resp = requests.get(https_url, timeout=TIMEOUT, allow_redirects=True)
        headers = {k.lower(): v for k, v in resp.headers.items()}
    except requests.exceptions.RequestException as exc:
        return [make_error(
            "security_headers", "Security Headers", Category.WEB_SECURITY,
            f"Could not fetch {https_url}: {exc}",
        )]

    findings: list[Finding] = []
    for finding_id, header_name, why, how, severity in _HEADER_CHECKS:
        header_key = header_name.lower()
        if header_key in headers:
            findings.append(make_pass(
                finding_id, header_name, Category.WEB_SECURITY,
                f"{header_name} is present: {headers[header_key]}",
                evidence={"value": headers[header_key]},
            ))
        else:
            findings.append(Finding(
                id=finding_id,
                title=f"Missing {header_name} header",
                category=Category.WEB_SECURITY,
                severity=severity,
                status=FindingStatus.ISSUE,
                description=f"{header_name} was not found on {https_url}.",
                business_impact=why,
                recommendation=how,
                effort=Effort.LOW,
            ))
    return findings



def run(domain: str) -> list[Finding]:
    """Run all web checks for a domain and return combined findings."""
    findings: list[Finding] = []
    findings.extend(scan_https_redirect(domain))
    findings.extend(scan_security_headers(domain))

    return findings

