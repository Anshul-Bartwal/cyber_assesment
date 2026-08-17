"""
Port / exposure scanner.

Covers spec section 8. Intentionally limited to a small, well-known set
of ports - NOT a full 1-65535 scan. This checks TCP connect only (no
banner grabbing, no exploitation, no aggressive probing), which is safe
against domains the user has authorized for assessment.

Important: an open port is not automatically a vulnerability (spec
section 8). The severities below reflect general, well-established
guidance (e.g. "database ports open to the internet are high risk") but
the risk engine (Phase 3) may still adjust these using business context.
"""

from __future__ import annotations

from ast import List
import socket

from backend.models.finding import (
    Finding, Severity, Effort, Category, FindingStatus, make_pass,make_error
)

TIMEOUT = 3
#ports: (service,severity if found,remark)
COMMON_PORTS={
    21: ("FTP",Severity.HIGH,"FTP transmits credentials unencrypted."),
    23: ("Telnet",Severity.HIGH,"Telnet transmits credentials unencrypted."),
    22: ("SSH",Severity.MEDIUM,"Common admin target; ensure key-based auth and rate limiting."),
    25:   ("SMTP", Severity.LOW, "Expected if this server sends mail directly."),
    53:   ("DNS", Severity.LOW, "Expected for authoritative DNS servers."),
    80:   ("HTTP", Severity.INFO, "Expected for web traffic; should redirect to HTTPS."),
    110:  ("POP3", Severity.MEDIUM, "Older mail protocol, often unencrypted."),
    143:  ("IMAP", Severity.MEDIUM, "Ensure this is the encrypted variant (IMAPS on 993) where possible."),
    443:  ("HTTPS", Severity.INFO, "Expected for web traffic."),
    # critical ports for databases and remote desktop
    3306: ("MySQL", Severity.CRITICAL, "Databases should not be directly reachable from the internet."),
    3389: ("RDP", Severity.CRITICAL, "A common target for brute-force and ransomware attacks."),
    5432: ("PostgreSQL", Severity.CRITICAL, "Databases should not be directly reachable from the internet."),
}

def _is_port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
        sock.settimeout(TIMEOUT)
        result=sock.connect_ex((host,port)) # better than connect as it returns an error code instead of raising an exception
    return result==0

def scan_ports(domain:str) -> list[Finding]:
    try:
        ip=socket.gethostbyname(domain)
    except socket.gaierror as exc:
        return [make_error(
            id="port_scan",
            title="Couldn't resolve domain",
            category=Category.NETWORK_EXPOSURE,
            description=f"DNS resolution failed for {domain}: {exc}"
        )]


    
    findings: list[Finding]=[]




    for port , (service,severity,remark) in COMMON_PORTS.items():
        try:

            is_open=_is_port_open(ip,port)
        except Exception as exc:
            findings.append(make_error(
                id=f"port_{port}",
                title=f"Error scanning port {port}",
                category=Category.NETWORK_EXPOSURE,
                description=f"Failed to scan port {port} on {domain}: {exc}"
            ))
            continue

        if not is_open:
            continue
        if severity == Severity.INFO:
            findings.append(make_pass(
                f"port_{port}", f"Port {port} ({service}) open - expected",
                Category.NETWORK_EXPOSURE,
                f"Port {port} ({service}) is open. {remark}",
                evidence={"port": port, "service": service},
            ))
            continue

        else:
            findings.append(Finding(
                id=f"port_{port}",
                title=f"Port {port} ({service}) is publicly exposed",
                category=Category.NETWORK_EXPOSURE,
                severity=severity,
                status=FindingStatus.ISSUE,
                description=f"Port {port} ({service}) responded to a connection attempt from the internet.",
                business_impact=remark,
                recommendation=(
                    f"Restrict access to port {port} ({service}) to a VPN, "
                    "allowlisted IPs, or a private network unless it must "
                    "be public. If it must be public, ensure strong "
                    "authentication and monitoring are in place."
                ),
                effort=Effort.MEDIUM,
                evidence={"port": port, "service": service},
            ))
        
    return findings      
        
def run(domain: str)-> list[Finding]:
    return scan_ports(domain)