"""

Runs every modular scanner (web, tls, dns, ports, technology, (to be made)) against a
domain and produces a single list of standardized Finding objects. This
replaces the monolithic Phase 1 scanner.py - the checks are the same in
spirit, but now:

    - each check lives in its own scanner module
    - every result is a full Finding (id, category, severity, business
      impact, recommendation, effort) instead of a bare PASS/FAIL

No scoring or prioritization logic lives here - that's Phase 3 (the risk
engine). This script only collects facts.

Usage:
    python scan.py example.com
    python scan.py example.com --json
    python scan.py example.com --only web,dns
"""

from __future__ import annotations

import argparse
import json
import sys

from backend.scanners import web
from backend.models.finding import Severity, FindingStatus

SCANNERS = {
    "web": web.run,

}

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

STATUS_COLOR = {
    FindingStatus.PASS: "\033[92m",   # green
    FindingStatus.ISSUE: "\033[91m",  # red
    FindingStatus.ERROR: "\033[90m",  # grey
}
RESET = "\033[0m"


def run_all(domain: str, only: list[str] | None = None) -> list:
    names = only if only else list(SCANNERS.keys())
    findings = []
    for name in names:
        scanner_fn = SCANNERS.get(name)
        if scanner_fn is None:
            print(f"Unknown scanner '{name}', skipping.", file=sys.stderr)
            continue
        try:
            findings.extend(scanner_fn(domain))
        except Exception as exc:  # noqa: BLE001 - a single scanner crashing
            # should not take down the whole scan.
            print(f"Scanner '{name}' raised an unexpected error: {exc}", file=sys.stderr)
    return findings

def print_human(domain: str, findings: list) -> None:
    print(f"\nCyberCheck - Phase 2 Scan Results for {domain}\n")
    findings_sorted = sorted(
        findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.category.value)
    )

    current_category = None
    for f in findings_sorted:
        if f.category.value != current_category:
            current_category = f.category.value
            print(f"\n== {current_category} ==")

        color = STATUS_COLOR.get(f.status, "")
        label = f.severity.value if f.status == FindingStatus.ISSUE else f.status.value
        print(f"  [{color}{label}{RESET}] {f.title}")
        if f.status == FindingStatus.ISSUE:
            print(f"      {f.description}")
            if f.recommendation:
                print(f"      -> {f.recommendation}")

    issues = [f for f in findings if f.status == FindingStatus.ISSUE]
    print(f"\n{len(issues)} issue(s) found out of {len(findings)} checks run.\n")

def print_json(domain: str, findings: list) -> None:
    payload = {"domain": domain, "findings": [f.to_dict() for f in findings]}
    print(json.dumps(payload, indent=2))


def main() -> int:
    parser = argparse.ArgumentParser(description="CyberCheck Phase 2 - modular scanner orchestrator.")
    parser.add_argument("domain", help="Domain to scan, e.g. example.com")
    parser.add_argument("--json", action="store_true", help="Output as JSON.")
    parser.add_argument(
        "--only", type=str, default=None,
        help=f"Comma-separated list of scanners to run: {', '.join(SCANNERS)}",
    )
    args = parser.parse_args()

    print(
        "Only scan assets you own or have explicit authorization to assess.",
        file=sys.stderr,
    )

    only = [s.strip() for s in args.only.split(",")] if args.only else None
    findings = run_all(args.domain, only)

    if args.json:
        print_json(args.domain, findings)
    else:
        print_human(args.domain, findings)

    return 1 if any(f.status == FindingStatus.ERROR for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
