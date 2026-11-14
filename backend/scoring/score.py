"""
Risk engine, part 2: category scores and the overall Security Score.

Methodology:

1. Each scanner Category maps to a scoring group (spec section 14):
     Web Security + TLS          -> Web Security
     Email Security              -> Email Security
     Network Exposure            -> Network Exposure
     Authentication              -> Authentication
     Business Practices + Backup -> Business Practices
   (Technology is informational only and is not scored.)

2. Group score = 100 - sum(risk points of its issues), floored at 0.

3. Overall score = weighted average of group scores, using the spec's
   initial weights (Web 20, Email 20, Network 25, Auth 20, Business 15).

4. Groups with no usable data are marked "not assessed" and EXCLUDED;
   the remaining weights are renormalized. Otherwise an unassessed
   group would silently score a free 100 and inflate the result (e.g.
   before the questionnaire exists, Authentication has no data).
   `coverage` reports what share of the total weight was actually
   assessed, so a score based on partial data is never presented as if
   it were complete.

Weights are initial assumptions (spec section 14) and may change after
testing - they live in one dict below for that reason.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from models.finding import Category, Finding, FindingStatus
from scoring.risk import risk_points

WEB = "Web Security"
EMAIL = "Email Security"
NETWORK = "Network Exposure"
AUTH = "Authentication"
BUSINESS = "Business Practices"

WEIGHTS = {WEB: 20, EMAIL: 20, NETWORK: 25, AUTH: 20, BUSINESS: 15}

CATEGORY_TO_GROUP = {
    Category.WEB_SECURITY: WEB,
    Category.TLS: WEB,
    Category.EMAIL_SECURITY: EMAIL,
    Category.NETWORK_EXPOSURE: NETWORK,
    Category.AUTHENTICATION: AUTH,
    Category.BUSINESS_PRACTICES: BUSINESS,
    Category.BACKUP_RECOVERY: BUSINESS,
}


@dataclass
class GroupScore:
    name: str
    weight: int
    assessed: bool
    score: int | None = None
    risk_points: float = 0.0
    issue_count: int = 0


@dataclass
class ScoreResult:
    overall: int | None
    coverage: int  # % of total weight that was actually assessed
    groups: dict[str, GroupScore] = field(default_factory=dict)
    error_count: int = 0  # checks that could not run (lowers confidence)

    def to_dict(self) -> dict:
        return {
            "overall": self.overall,
            "coverage_percent": self.coverage,
            "checks_that_could_not_run": self.error_count,
            "categories": {
                n: {
                    "score": g.score,
                    "assessed": g.assessed,
                    "weight": g.weight,
                    "issues": g.issue_count,
                    "risk_points": g.risk_points,
                }
                for n, g in self.groups.items()
            },
        }


def calculate_score(findings: list[Finding]) -> ScoreResult:
    points = {g: 0.0 for g in WEIGHTS}
    issues = {g: 0 for g in WEIGHTS}
    has_data = {g: False for g in WEIGHTS}
    errors = 0

    for f in findings:
        if f.status == FindingStatus.ERROR:
            errors += 1
        group = CATEGORY_TO_GROUP.get(f.category)
        if group is None:
            continue  # e.g. Technology: informational, not scored
        if f.status in (FindingStatus.PASS, FindingStatus.ISSUE):
            has_data[group] = True
        if f.status == FindingStatus.ISSUE and risk_points(f) > 0:
            issues[group] += 1
        points[group] += risk_points(f)

    groups: dict[str, GroupScore] = {}
    for name, weight in WEIGHTS.items():
        if not has_data[name]:
            groups[name] = GroupScore(name, weight, assessed=False)
            continue
        score = max(0, round(100 - points[name]))
        groups[name] = GroupScore(
            name, weight, True, score, points[name], issues[name]
        )

    assessed = [g for g in groups.values() if g.assessed]
    total_weight = sum(WEIGHTS.values())
    assessed_weight = sum(g.weight for g in assessed)

    overall = None
    if assessed_weight:
        overall = round(sum(g.score * g.weight for g in assessed) / assessed_weight)

    return ScoreResult(
        overall=overall,
        coverage=round(100 * assessed_weight / total_weight),
        groups=groups,
        error_count=errors,
    )
