"""
Standardized Finding model.

Core architectural principle (spec section 12):

    SCANNERS FIND FACTS.
    RISK ENGINE INTERPRETS THOSE FACTS.

Every scanner module in `scanners/` must return a list of `Finding`
objects using this exact shape, regardless of what it checks internally.
That's what lets the risk engine (Phase 3) treat a missing DMARC record
and an exposed RDP port the same way: as inputs with a severity, a
category, and an effort estimate, without needing to know anything
about DNS or sockets.

A scanner assigns *initial* severity based on well-established security
guidance (e.g. "exposed RDP is high risk"). The risk engine may later
adjust that severity using business-questionnaire context (Phase 4) -
that recalculation belongs in scoring/risk.py, not here.
"""



from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"  # passed checks / neutral facts worth recording

class Effort(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

class Category(str, Enum):
    WEB_SECURITY = "Web Security"
    EMAIL_SECURITY = "Email Security"
    NETWORK_EXPOSURE = "Network Exposure"
    TLS = "TLS"
    TECHNOLOGY = "Technology"
    AUTHENTICATION = "Authentication"
    BUSINESS_PRACTICES = "Business Practices"
    BACKUP_RECOVERY = "Backup / Recovery"


class FindingStatus(str, Enum):
    """Whether the underlying check passed or identified a real issue.

    Kept separate from Severity: a PASS finding still gets recorded (with
    severity=INFO) so the report can show what's working, not just what's
    broken - see spec section 20/21 example dashboards.
    """
    PASS = "PASS"
    ISSUE = "ISSUE"
    ERROR = "ERROR"  # scanner could not complete the check
@dataclass
class Finding:
    """A single fact discovered by a scanner, with severity and context.

    This is the standardized shape that all scanners must return, so the
    risk engine can treat all findings the same way.
    """

    id: str
    title: str
    category: Category
    severity: Severity
    status: FindingStatus
    description: str
    business_impact: str = ""
    recommendation: str = ""
    effort: Effort = Effort.LOW
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        # Enums need to become their plain string values for JSON output.
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        d["effort"] = self.effort.value
        return d

def make_pass(
        id:str,
        title:str,
        category:Category,
        description:str,
        evidence:dict|None=None
        ) -> Finding:
    """Return a Finding object representing a passed check.

    The scanner found no issue, but we still want to record the fact that
    the check was performed and passed.
    """
    return Finding(
        id=id,
        title=title,
        category=category,
        severity=Severity.INFO,
        status=FindingStatus.PASS,
        description=description,
        evidence=evidence or {},
    )

def make_error(
        id:str,
        title:str,
        category:Category,
        description:str
        ) -> Finding:
    """Return a Finding object representing an error in the scan.

    The scanner encountered an issue while trying to perform the check.
    """
    return Finding(
        id=id,
        title=title,
        category=category,
        severity=Severity.INFO,
        status=FindingStatus.ERROR,
        description=description,
        evidence={},
    )