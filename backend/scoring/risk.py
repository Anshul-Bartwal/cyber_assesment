"""
Risk engine, part 1: per-finding risk points and prioritization.

Scanners find facts; this module interprets them.

Methodology (documented so it can be defended):

  risk points = impact points (from severity) x likelihood

  CRITICAL = 20, HIGH = 10, MEDIUM = 5, LOW = 2, INFO = 0

Likelihood defaults to 1.0 for every finding. The hook exists so that
Phase 4 (questionnaire context) or later threat-intel can raise/lower
it, but no arbitrary multipliers are invented here.

Prioritization ("what should I fix first?"):

  priority = risk points / effort weight   (LOW=1, MEDIUM=2, HIGH=3)

High impact + low effort floats to the top. Ties break on raw severity,
then finding id (so output is deterministic).
"""

from __future__ import annotations

from models.finding import Effort, Finding, FindingStatus, Severity

SEVERITY_POINTS = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

EFFORT_WEIGHT = {
    Effort.LOW: 1,
    Effort.MEDIUM: 2,
    Effort.HIGH: 3,
}

DEFAULT_LIKELIHOOD = 1.0


def risk_points(finding: Finding, likelihood: float = DEFAULT_LIKELIHOOD) -> float:
    """Points a finding contributes to risk. Only real issues count:
    PASS and ERROR findings contribute nothing."""
    if finding.status != FindingStatus.ISSUE:
        return 0.0
    return SEVERITY_POINTS[finding.severity] * likelihood


def priority_score(finding: Finding) -> float:
    return risk_points(finding) / EFFORT_WEIGHT[finding.effort]


def prioritize(findings: list[Finding], limit: int | None = 3) -> list[Finding]:
    """Return issues ranked by 'impact per unit of effort'."""
    issues = [f for f in findings if risk_points(f) > 0]
    issues.sort(
        key=lambda f: (-priority_score(f), -SEVERITY_POINTS[f.severity], f.id)
    )
    return issues if limit is None else issues[:limit]


def impact_effort_label(finding: Finding) -> str:
    """Human-readable e.g. 'High impact / Low effort'."""
    impact = {
        Severity.CRITICAL: "Critical", Severity.HIGH: "High",
        Severity.MEDIUM: "Medium", Severity.LOW: "Low", Severity.INFO: "Info",
    }[finding.severity]
    return f"{impact} impact / {finding.effort.value.capitalize()} effort"
