"""
DNS / email security scanner.

Covers spec section 7: SPF, DMARC, DKIM (best-effort), MX records.

Named `dns_scanner.py` rather than `dns.py` to avoid shadowing Python's
own `dns` package (dnspython), which this module imports.
"""

from __future__ import annotations

from backend.models.finding import (
    Finding, Severity, Effort, Category, FindingStatus, make_pass, make_error,
)

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class _DnsUnavailableError(Exception):
    pass


def _require_dns() -> None:
    if not DNS_AVAILABLE:
        raise _DnsUnavailableError(
            "dnspython is not installed. Run: pip install dnspython"
        )

# Common DKIM selectors used by widely-adopted email providers. This is a
# best-effort check only - spec 7.3 explicitly says not to claim DKIM is
# absent just because a selector couldn't be discovered.
_COMMON_DKIM_SELECTORS = [
    "google", "selector1", "selector2",  # Google Workspace / Microsoft 365
    "k1", "k2",                          # Mailchimp / Sendgrid-style
    "default", "dkim", "mail",
]


def _query_txt(name: str) -> list[str]:
    _require_dns()
    try:
        answers = dns.resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    return [
        b"".join(rdata.strings).decode("utf-8", errors="replace")
        for rdata in answers
    ]


def scan_spf(domain: str) -> list[Finding]:
    try:
        records = _query_txt(domain)
    except _DnsUnavailableError as exc:
        return [make_error("spf", "SPF", Category.EMAIL_SECURITY, str(exc))]
    except dns.exception.DNSException as exc:
        return [make_error(
            "spf", "SPF", Category.EMAIL_SECURITY, f"DNS lookup failed: {exc}",
        )]

    spf_records = [r for r in records if r.lower().startswith("v=spf1")]

    if not spf_records:
        return [Finding(
            id="spf",
            title="SPF record is not configured",
            category=Category.EMAIL_SECURITY,
            severity=Severity.HIGH,
            status=FindingStatus.ISSUE,
            description=f"No TXT record starting with 'v=spf1' was found for {domain}.",
            business_impact=(
                "Without SPF, receiving mail servers have no way to verify "
                "whether an email claiming to be from this domain was sent "
                "by an authorized server, making it easier for attackers "
                "to spoof this domain in phishing emails."
            ),
            recommendation=(
                "Publish an SPF TXT record listing the mail servers "
                "authorized to send email for this domain, e.g. "
                "'v=spf1 include:_spf.google.com ~all'."
            ),
            effort=Effort.LOW,
        )]

    if len(spf_records) > 1:
        return [Finding(
            id="spf",
            title="Multiple SPF records found",
            category=Category.EMAIL_SECURITY,
            severity=Severity.MEDIUM,
            status=FindingStatus.ISSUE,
            description=(
                f"{len(spf_records)} TXT records starting with 'v=spf1' "
                f"were found. Per RFC 7208, a domain must have at most one, "
                "and multiple records cause undefined/unpredictable behavior."
            ),
            business_impact=(
                "Mail servers may handle conflicting SPF records "
                "inconsistently, which can cause legitimate email to fail "
                "authentication or spoofed email to pass unexpectedly."
            ),
            recommendation="Merge all authorized senders into a single SPF record.",
            effort=Effort.LOW,
            evidence={"records": spf_records},
        )]

    return [make_pass(
        "spf", "SPF", Category.EMAIL_SECURITY,
        f"SPF record found: {spf_records[0]}",
        evidence={"record": spf_records[0]},
    )]


_DMARC_POLICY_INFO = {
    "reject": (Severity.INFO, FindingStatus.PASS,
               "Policy is 'reject' - mail failing authentication is blocked."),
    "quarantine": (Severity.LOW, FindingStatus.ISSUE,
                   "Policy is 'quarantine' - failing mail is flagged/spam-foldered, not blocked."),
    "none": (Severity.MEDIUM, FindingStatus.ISSUE,
             "Policy is 'none' - DMARC is monitoring only; spoofed mail is still delivered."),
}


def scan_dmarc(domain: str) -> list[Finding]:
    dmarc_name = f"_dmarc.{domain}"
    try:
        records = _query_txt(dmarc_name)
    except _DnsUnavailableError as exc:
        return [make_error("dmarc", "DMARC", Category.EMAIL_SECURITY, str(exc))]
    except dns.exception.DNSException as exc:
        return [make_error(
            "dmarc", "DMARC", Category.EMAIL_SECURITY, f"DNS lookup failed: {exc}",
        )]

    dmarc_records = [r for r in records if r.lower().startswith("v=dmarc1")]

    if not dmarc_records:
        return [Finding(
            id="dmarc",
            title="DMARC is not configured",
            category=Category.EMAIL_SECURITY,
            severity=Severity.HIGH,
            status=FindingStatus.ISSUE,
            description=f"No DMARC record found at {dmarc_name}.",
            business_impact=(
                "Attackers may have an easier time impersonating this "
                "domain in phishing emails, since receiving servers have "
                "no domain-owner-specified policy for handling mail that "
                "fails SPF/DKIM."
            ),
            recommendation=(
                "Publish a DMARC TXT record at "
                f"'{dmarc_name}', starting with a monitoring policy "
                "(p=none) and moving to p=quarantine or p=reject over time."
            ),
            effort=Effort.LOW,
        )]

    record = dmarc_records[0]
    policy = "unknown"
    for part in record.split(";"):
        part = part.strip()
        if part.lower().startswith("p="):
            policy = part.split("=", 1)[1].strip().lower()
            break

    severity, status, policy_note = _DMARC_POLICY_INFO.get(
        policy, (Severity.MEDIUM, FindingStatus.ISSUE, f"Unrecognized policy value '{policy}'.")
    )

    return [Finding(
        id="dmarc",
        title="DMARC configured" if status == FindingStatus.PASS else f"DMARC policy is weak (p={policy})",
        category=Category.EMAIL_SECURITY,
        severity=severity,
        status=status,
        description=f"DMARC record found at {dmarc_name}. {policy_note}",
        business_impact=(
            "" if status == FindingStatus.PASS else
            "A weak or monitoring-only DMARC policy means spoofed email "
            "impersonating this domain can still reach recipients' inboxes."
        ),
        recommendation=(
            "" if status == FindingStatus.PASS else
            "Move the DMARC policy toward 'p=quarantine' or 'p=reject' "
            "once SPF/DKIM alignment has been confirmed via DMARC reports."
        ),
        effort=Effort.MEDIUM,
        evidence={"record": record, "policy": policy},
    )]


def scan_dkim(domain: str) -> list[Finding]:
    """Best-effort DKIM check against a small list of common selectors.

    Per spec 7.3: this is advisory only. A finding here is PASS if any
    common selector resolves, and INFO (not FAIL) otherwise - absence of
    evidence is not evidence of absence for DKIM.
    """
    if not DNS_AVAILABLE:
        return [make_error(
            "dkim", "DKIM (best-effort)", Category.EMAIL_SECURITY,
            "dnspython is not installed. Run: pip install dnspython",
        )]

    found_selectors = []
    for selector in _COMMON_DKIM_SELECTORS:
        name = f"{selector}._domainkey.{domain}"
        try:
            records = _query_txt(name)
        except (_DnsUnavailableError, dns.exception.DNSException):
            continue
        if any("v=dkim1" in r.lower() or "p=" in r.lower() for r in records):
            found_selectors.append(selector)

    if found_selectors:
        return [make_pass(
            "dkim", "DKIM (best-effort)", Category.EMAIL_SECURITY,
            f"Found a DKIM record under common selector(s): {', '.join(found_selectors)}.",
            evidence={"selectors": found_selectors},
        )]

    return [Finding(
        id="dkim",
        title="DKIM not confirmed (advisory only)",
        category=Category.EMAIL_SECURITY,
        severity=Severity.INFO,
        status=FindingStatus.ERROR,
        description=(
            "No DKIM record was found under common selectors. This does "
            "NOT mean DKIM is absent - custom or provider-specific "
            "selectors are common and were not checked."
        ),
        recommendation=(
            "Confirm DKIM configuration directly with your email provider "
            "if unsure."
        ),
    )]


def scan_mx(domain: str) -> list[Finding]:
    try:
        _require_dns()
        answers = dns.resolver.resolve(domain, "MX")
    except _DnsUnavailableError as exc:
        return [make_error("mx", "MX Records", Category.EMAIL_SECURITY, str(exc))]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [Finding(
            id="mx",
            title="No MX records found",
            category=Category.EMAIL_SECURITY,
            severity=Severity.INFO,
            status=FindingStatus.ISSUE,
            description=f"No MX records found for {domain}. This domain may not receive email directly.",
            recommendation="Confirm this is expected if the domain is not used for email.",
        )]
    except dns.exception.DNSException as exc:
        return [make_error(
            "mx", "MX Records", Category.EMAIL_SECURITY, f"DNS lookup failed: {exc}",
        )]

    hosts = sorted(str(r.exchange).rstrip(".") for r in answers)
    return [make_pass(
        "mx", "MX Records", Category.EMAIL_SECURITY,
        f"{len(hosts)} MX record(s) found: {', '.join(hosts)}.",
        evidence={"mx_hosts": hosts},
    )]


def run(domain: str) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(scan_spf(domain))
    findings.extend(scan_dmarc(domain))
    findings.extend(scan_dkim(domain))
    findings.extend(scan_mx(domain))
    return findings


