
"""
CyberCheck - Phase 1 CLI Scanner

A learning-focused command-line scanner that checks a small set of
high-value, non-intrusive security signals for an authorized domain:

    - HTTPS enforcement (does HTTP redirect to HTTPS?)
    - Security headers (HSTS, CSP, X-Frame-Options)
    - Email security (SPF, DMARC)

This is intentionally simple. It is Phase 1 of the CyberCheck roadmap:
the goal is to understand HTTP, DNS, and headers before building
modular scanners, a risk engine, or a UI.

IMPORTANT: Only run this against domains you own or are explicitly
authorized to assess.

Usage:
    python scanner.py example.com
    python scanner.py example.com --json
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from enum import Enum

import requests

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

class CheckStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    ERROR = "ERROR"  # scan could not be completed (network issue, etc.)


@dataclass
class CheckResult:
    """A single, standardized check outcome.

    Keeping this shape consistent now makes it trivial later to convert
    each result into a full 'Finding' object (see project spec section 12)
    once the risk engine exists.
    """
    check_id: str
    title: str
    status: CheckStatus
    detail: str = ""
    raw: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# HTTP timeout / shared config
# ---------------------------------------------------------------------------

TIMEOUT = 8  # seconds - keep scans fast and avoid hanging on dead hosts


# ---------------------------------------------------------------------------
# 1. HTTPS enforcement check
# ---------------------------------------------------------------------------

def check_https_redirect(domain: str) -> CheckResult:
    """Does http://domain redirect to https://domain?

    Concept: a business site that is reachable over plain HTTP without
    being redirected to HTTPS may transmit data (including login forms)
    unencrypted if a user happens to type the http:// version.
    """
    http_url = f"http://{domain}"
    try:
        resp = requests.get(http_url, timeout=TIMEOUT, allow_redirects=True)
    except requests.exceptions.SSLError:
        return CheckResult(
            "https_redirect", "HTTPS Redirect", CheckStatus.ERROR,
            "TLS error while following redirects.",
        )
    except requests.exceptions.ConnectionError:
        # Port 80 might simply be closed - some sites disable HTTP entirely,
        # which is actually fine from a security standpoint.
        return CheckResult(
            "https_redirect", "HTTPS Redirect", CheckStatus.PASS,
            "Port 80 is not reachable (HTTP appears disabled entirely).",
        )
    except requests.exceptions.RequestException as exc:
        return CheckResult(
            "https_redirect", "HTTPS Redirect", CheckStatus.ERROR, str(exc),
        )

    final_url = resp.url
    if final_url.startswith("https://"):
        return CheckResult(
            "https_redirect", "HTTPS Redirect", CheckStatus.PASS,
            f"http://{domain} redirects to {final_url}",
        )

    return CheckResult(
        "https_redirect", "HTTPS Redirect", CheckStatus.FAIL,
        f"http://{domain} remained on HTTP (final URL: {final_url})",
    )


# ---------------------------------------------------------------------------
# 2. TO DO : Security headers check
# ---------------------------------------------------------------------------
def check_security_headers(domain: str) -> list[CheckResult]:
    """Fetch https://domain and inspect a handful of security headers.
 
    Concept: these headers are instructions the server gives the browser
    about how to behave defensively (e.g. "only ever load me over HTTPS",
    "don't let other sites put me in an iframe"). Missing headers are not
    automatically vulnerabilities - see spec section 5.2 - but their
    absence is a useful signal worth surfacing.
    """
    https_url = f"https://{domain}"
    results: list[CheckResult] = []
 
    try:
        resp = requests.get(https_url, timeout=TIMEOUT, allow_redirects=True)
        headers = {k.lower(): v for k, v in resp.headers.items()}
    except requests.exceptions.RequestException as exc:
        error = CheckResult(
            "security_headers", "Security Headers", CheckStatus.ERROR,
            f"Could not fetch {https_url}: {exc}",
        )
        return [error]
 
    header_checks = [ # check_id,title,header_key
        ("hsts", "Strict-Transport-Security", "strict-transport-security"),
        ("csp", "Content-Security-Policy", "content-security-policy"),
        ("x_frame_options", "X-Frame-Options", "x-frame-options"),
    ]
 
    for check_id, title, header_key in header_checks:
        if header_key in headers:
            results.append(CheckResult(
                check_id, title, CheckStatus.PASS,
                f"{title} present: {headers[header_key]}",
            ))
        else:
            results.append(CheckResult(
                check_id, title, CheckStatus.FAIL,
                f"{title} header was not found on {https_url}",
            ))
 
    return results
 
 


def run_scan(domain: str) -> list[CheckResult]:
    results: list[CheckResult] = []
    results.append(check_https_redirect(domain))
    results.extend(check_security_headers(domain))
    return results
 
 
STATUS_SYMBOL = {
    CheckStatus.PASS: "\033[92mPASS\033[0m",
    CheckStatus.FAIL: "\033[91mFAIL\033[0m",
    CheckStatus.WARN: "\033[93mWARN\033[0m",
    CheckStatus.ERROR: "\033[90mERROR\033[0m",
}
 
 
def print_human(domain: str, results: list[CheckResult]) -> None:
    print(f"\nCyberCheck - Phase 1 Scan Results for {domain}\n")
    print("-" * 60)
    for r in results:
        symbol = STATUS_SYMBOL.get(r.status, r.status.value)
        print(f"{r.title:<28} {symbol}")
        if r.detail:
            print(f"    {r.detail}")
    print("-" * 60)
 
    passed = sum(1 for r in results if r.status == CheckStatus.PASS)
    total = len(results)
    print(f"\n{passed}/{total} checks passed.\n")
 
 
def print_json(domain: str, results: list[CheckResult]) -> None:
    payload = {
        "domain": domain,
        "results": [
            {
                "id": r.check_id,
                "title": r.title,
                "status": r.status.value,
                "detail": r.detail,
            }
            for r in results
        ],
    }
    print(json.dumps(payload, indent=2))
 
 
def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "CyberCheck Phase 1 - a minimal, safe security scanner. "
            "Only scan domains you own or are explicitly authorized to assess."
        )
    )
    parser.add_argument("domain", help="Domain to scan, e.g. example.com")
    parser.add_argument(
        "--json", action="store_true",
        help="Output results as JSON instead of human-readable text.",
    )
    args = parser.parse_args()
 
    print(
        "Only scan assets you own or have explicit authorization to assess.",
        file=sys.stderr,
    )
 
    results = run_scan(args.domain)
 
    if args.json:
        print_json(args.domain, results)
    else:
        print_human(args.domain, results)
 
    # Exit non-zero if any check ERRORed, useful for CI/scripting later.
    if any(r.status == CheckStatus.ERROR for r in results):
        return 1
    return 0
 
 
if __name__ == "__main__":
    sys.exit(main())
 
