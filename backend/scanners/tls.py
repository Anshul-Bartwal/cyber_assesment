"""
TLS scanner using Python's built-in ssl/socket modules.

Covers spec section 6. Deliberately basic for the MVP: certificate
validity, expiry, hostname match, and negotiated TLS version. No
cipher-suite auditing or deep cryptographic analysis.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from backend.models.finding import (
    Finding, Severity, Effort, Category, FindingStatus, make_pass, make_error,
)

PORT = 443
TIMEOUT = 8
EXPIRY_WARNING_DAYS = 30


def _parse_cert_date(date_str: str) -> datetime:
    # Format used by ssl module, e.g. 'Jun  1 12:00:00 2026 GMT'
    return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc
    )


def scan_certificate(domain: str) -> list[Finding]:
    context = ssl.create_default_context()

    try:
        with socket.create_connection((domain, PORT), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()
    except ssl.SSLCertVerificationError as exc:
        return [Finding(
            id="tls_certificate",
            title="TLS certificate failed validation",
            category=Category.TLS,
            severity=Severity.HIGH,
            status=FindingStatus.ISSUE,
            description=f"Certificate validation failed for {domain}:{PORT}: {exc}",
            business_impact=(
                "Browsers will show visitors a security warning, which "
                "damages trust and may cause visitors to leave the site. "
                "It can also indicate the connection is not securely "
                "authenticated, exposing traffic to interception."
            ),
            recommendation=(
                "Install a valid certificate from a trusted certificate "
                "authority covering this exact hostname, and ensure the "
                "certificate chain is complete."
            ),
            effort=Effort.MEDIUM,
        )]
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        return [make_error(
            "tls_certificate", "TLS Certificate", Category.TLS,
            f"Could not connect to {domain}:{PORT} to inspect the certificate: {exc}",
        )]

    findings: list[Finding] = []

    # Hostname match is already enforced by wrap_socket(server_hostname=...)
    # raising SSLCertVerificationError above if it fails, so reaching here
    # means both validity and hostname match succeeded.
    findings.append(make_pass(
        "tls_certificate_valid", "TLS Certificate Validity", Category.TLS,
        f"Certificate for {domain} is valid and matches the hostname.",
    ))

    # Expiry check
    not_after_raw = cert.get("notAfter")
    if not_after_raw:
        expires_at = _parse_cert_date(not_after_raw)
        days_remaining = (expires_at - datetime.now(timezone.utc)).days

        if days_remaining < 0:
            findings.append(Finding(
                id="tls_certificate_expiry",
                title="TLS certificate has expired",
                category=Category.TLS,
                severity=Severity.CRITICAL,
                status=FindingStatus.ISSUE,
                description=f"The certificate expired on {not_after_raw}.",
                business_impact=(
                    "Visitors will see browser security warnings and may "
                    "be unable to connect at all, and any automated "
                    "systems relying on this connection may fail."
                ),
                recommendation="Renew the TLS certificate immediately.",
                effort=Effort.LOW,
                evidence={"expires": not_after_raw},
            ))
        elif days_remaining <= EXPIRY_WARNING_DAYS:
            findings.append(Finding(
                id="tls_certificate_expiry",
                title="TLS certificate expiring soon",
                category=Category.TLS,
                severity=Severity.MEDIUM,
                status=FindingStatus.ISSUE,
                description=f"The certificate expires in {days_remaining} day(s) ({not_after_raw}).",
                business_impact=(
                    "If not renewed in time, visitors will see browser "
                    "security warnings and secure connections may fail."
                ),
                recommendation="Renew the certificate, and consider enabling auto-renewal (e.g. Let's Encrypt/ACME).",
                effort=Effort.LOW,
                evidence={"expires": not_after_raw, "days_remaining": days_remaining},
            ))
        else:
            findings.append(make_pass(
                "tls_certificate_expiry", "TLS Certificate Expiry", Category.TLS,
                f"Certificate is valid for {days_remaining} more day(s) (expires {not_after_raw}).",
                evidence={"expires": not_after_raw, "days_remaining": days_remaining},
            ))

    # TLS version check
    outdated_versions = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}
    if tls_version in outdated_versions:
        findings.append(Finding(
            id="tls_version",
            title=f"Outdated TLS version in use ({tls_version})",
            category=Category.TLS,
            severity=Severity.HIGH,
            status=FindingStatus.ISSUE,
            description=f"The server negotiated {tls_version}, which is deprecated.",
            business_impact=(
                "Older TLS versions have known cryptographic weaknesses "
                "and are increasingly rejected by modern browsers and "
                "compliance frameworks."
            ),
            recommendation="Disable TLS 1.0/1.1/SSLv2/v3 and require TLS 1.2 or higher.",
            effort=Effort.MEDIUM,
            evidence={"tls_version": tls_version},
        ))
    else:
        findings.append(make_pass(
            "tls_version", "TLS Version", Category.TLS,
            f"Server negotiated {tls_version}.",
            evidence={"tls_version": tls_version},
        ))

    return findings


def run(domain: str) -> list[Finding]:
    return scan_certificate(domain)
