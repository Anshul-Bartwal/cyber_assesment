"""
Business security questionnaire (spec section 11).

Each question maps to a standardized Finding, exactly like the technical
scanners, so the risk engine scores questionnaire answers and scan
results the same way. Nothing in scoring/ needed to change.

Answer handling:
  yes     -> PASS finding (control is in place)
  no      -> ISSUE finding
  unsure  -> ISSUE finding, worded as "could not be confirmed". If the
             owner can't say whether a control exists, we can't credit
             it either; this keeps the score honest rather than generous.
  (unanswered questions produce no finding and are not scored)

Follow-up questions (`depends_on`) are only scored when their parent
answer is "yes". Example: "are backups tested?" is meaningless if there
are no backups, and the missing backup is already penalized once.

Severities and efforts are initial judgments based on common small
business guidance (e.g. NIST CSF 2.0 small business quick-start, CISA
basic cyber hygiene). They live in this one table so they're easy to
review and tune after testing.
"""

from __future__ import annotations

from dataclasses import dataclass

from models.finding import (
    Category, Effort, Finding, FindingStatus, Severity, make_pass,
)

VALID_ANSWERS = {"yes", "no", "unsure"}


@dataclass(frozen=True)
class Question:
    id: str
    section: str          # heading shown in the UI
    text: str
    help: str
    category: Category
    severity: Severity    # severity if the control is missing
    effort: Effort
    issue_title: str
    issue_description: str
    business_impact: str
    recommendation: str
    pass_description: str
    depends_on: str | None = None


QUESTIONS: list[Question] = [
    # ---------------- Accounts & passwords ----------------
    Question(
        id="mfa",
        section="Accounts & passwords",
        text="Is multi-factor authentication (MFA) turned on for employee accounts such as email and cloud tools?",
        help="MFA asks for a second proof of identity, like a code from a phone app, in addition to the password.",
        category=Category.AUTHENTICATION,
        severity=Severity.HIGH,
        effort=Effort.LOW,
        issue_title="Multi-factor authentication (MFA) is not enabled",
        issue_description="MFA is not turned on for all employee accounts.",
        business_impact="One stolen or guessed password is enough for an attacker to take over an account, read email, redirect payments, or reach customer data.",
        recommendation="Turn on MFA for email and admin accounts first, then other business tools. Authenticator apps or security keys are stronger than text-message codes.",
        pass_description="MFA is enabled for employee accounts.",
    ),
    Question(
        id="unique_accounts",
        section="Accounts & passwords",
        text="Does every employee have their own individual account (no shared logins)?",
        help="Shared logins make it impossible to know who did what, or to remove one person's access.",
        category=Category.AUTHENTICATION,
        severity=Severity.MEDIUM,
        effort=Effort.MEDIUM,
        issue_title="Employees share accounts",
        issue_description="Not every employee has a unique, individual account.",
        business_impact="Shared logins hide who made a change, and one person leaving means changing the password for everyone who uses it.",
        recommendation="Create an individual account for each person and retire shared logins.",
        pass_description="Every employee has an individual account.",
    ),
    Question(
        id="offboarding",
        section="Accounts & passwords",
        text="When someone leaves the business, are their accounts disabled right away?",
        help="This includes email, cloud tools, and any admin panels they could access.",
        category=Category.AUTHENTICATION,
        severity=Severity.MEDIUM,
        effort=Effort.LOW,
        issue_title="Former employee accounts may stay active",
        issue_description="Accounts of people who have left are not reliably disabled right away.",
        business_impact="Old accounts are an easy way in for a disgruntled ex-employee or for an attacker who finds the old credentials.",
        recommendation="Keep a simple checklist for departures that includes disabling every account the same day.",
        pass_description="Accounts are disabled promptly when employees leave.",
    ),
    Question(
        id="password_manager",
        section="Accounts & passwords",
        text="Does the business use a password manager?",
        help="A password manager creates and stores strong, unique passwords so people don't reuse them.",
        category=Category.AUTHENTICATION,
        severity=Severity.MEDIUM,
        effort=Effort.LOW,
        issue_title="No password manager in use",
        issue_description="The business does not use a password manager.",
        business_impact="Without one, people tend to reuse weak passwords, so a leak from one website can unlock the others.",
        recommendation="Adopt a business password manager and have everyone use it for work accounts.",
        pass_description="A password manager is in use.",
    ),
    Question(
        id="private_passwords",
        section="Accounts & passwords",
        text="Are passwords kept private to each person (not shared between employees or written on notes)?",
        help="Answer 'yes' if nobody shares passwords with coworkers.",
        category=Category.AUTHENTICATION,
        severity=Severity.MEDIUM,
        effort=Effort.LOW,
        issue_title="Passwords are shared between employees",
        issue_description="Passwords are shared between people or left where others can see them.",
        business_impact="Shared passwords spread quickly and can't be revoked for one person without disrupting everyone.",
        recommendation="Use individual accounts, and a password manager's sharing feature for the rare cases where access must be shared.",
        pass_description="Passwords are kept private to each person.",
    ),
    # ---------------- Backups ----------------
    Question(
        id="backup_exists",
        section="Backups",
        text="Are important business files and data backed up?",
        help="Think customer records, financial files, and anything you couldn't easily recreate.",
        category=Category.BACKUP_RECOVERY,
        severity=Severity.HIGH,
        effort=Effort.MEDIUM,
        issue_title="Important data is not reliably backed up",
        issue_description="Important business data is not regularly backed up.",
        business_impact="Ransomware, hardware failure, or an accidental deletion could mean permanent loss of data the business depends on.",
        recommendation="Set up automatic, regular backups of important files and systems.",
        pass_description="Important data is backed up.",
    ),
    Question(
        id="backup_separate",
        section="Backups",
        text="Are backups stored separately from the main systems (offline or in a different location)?",
        help="A backup on the same computer or network can be lost or encrypted by the same attack.",
        category=Category.BACKUP_RECOVERY,
        severity=Severity.MEDIUM,
        effort=Effort.MEDIUM,
        issue_title="Backups are not stored separately",
        issue_description="Backups are kept in the same place as the main systems.",
        business_impact="Ransomware and disasters often destroy backups that sit alongside the original data.",
        recommendation="Keep at least one copy offline or in a separate cloud account that normal logins can't modify.",
        pass_description="Backups are stored separately from main systems.",
        depends_on="backup_exists",
    ),
    Question(
        id="backup_tested",
        section="Backups",
        text="Are backups regularly tested by restoring some data?",
        help="A backup you've never restored from may not actually work.",
        category=Category.BACKUP_RECOVERY,
        severity=Severity.MEDIUM,
        effort=Effort.LOW,
        issue_title="Backups are not tested",
        issue_description="Backup restores are not regularly tested.",
        business_impact="Untested backups often turn out to be incomplete or unusable at exactly the moment they're needed.",
        recommendation="Restore a sample of files every few months and note that it worked.",
        pass_description="Backups are regularly tested.",
        depends_on="backup_exists",
    ),
    # ---------------- Updates ----------------
    Question(
        id="os_updates",
        section="Updates",
        text="Are computers and phones set to install operating system updates automatically?",
        help="Windows, macOS, iOS, and Android all have automatic update settings.",
        category=Category.BUSINESS_PRACTICES,
        severity=Severity.MEDIUM,
        effort=Effort.LOW,
        issue_title="Operating system updates are not automatic",
        issue_description="Devices are not set to update their operating systems automatically.",
        business_impact="Unpatched devices carry known flaws that attackers actively use.",
        recommendation="Enable automatic updates on all work computers and phones.",
        pass_description="Operating system updates are automatic.",
    ),
    Question(
        id="app_patching",
        section="Updates",
        text="Are important applications (browsers, website software, plugins) kept up to date?",
        help="This includes your website platform and its plugins, such as WordPress.",
        category=Category.BUSINESS_PRACTICES,
        severity=Severity.MEDIUM,
        effort=Effort.MEDIUM,
        issue_title="Applications are not regularly patched",
        issue_description="Important applications are not kept up to date on a regular schedule.",
        business_impact="Outdated website software and plugins are one of the most common ways small business sites get hacked.",
        recommendation="Turn on auto-updates where possible and set a monthly reminder to check the rest.",
        pass_description="Important applications are kept up to date.",
    ),
    # ---------------- Employee awareness ----------------
    Question(
        id="training",
        section="Employee awareness",
        text="Do employees receive cybersecurity or phishing awareness training?",
        help="Even a short yearly session helps people spot suspicious emails.",
        category=Category.BUSINESS_PRACTICES,
        severity=Severity.MEDIUM,
        effort=Effort.MEDIUM,
        issue_title="No cybersecurity awareness training",
        issue_description="Employees do not receive cybersecurity or phishing awareness training.",
        business_impact="Phishing emails are the most common way attackers get in, and untrained staff are far more likely to click.",
        recommendation="Run a short awareness session at least yearly and cover how to spot phishing emails.",
        pass_description="Employees receive security awareness training.",
    ),
    Question(
        id="report_suspicious",
        section="Employee awareness",
        text="Is there a clear way for employees to report suspicious emails?",
        help="For example, forwarding to a named person or a dedicated address.",
        category=Category.BUSINESS_PRACTICES,
        severity=Severity.LOW,
        effort=Effort.LOW,
        issue_title="No process for reporting suspicious emails",
        issue_description="Employees have no clear way to report suspicious emails.",
        business_impact="Without a reporting path, one person's near miss never warns the rest of the team.",
        recommendation="Name one person or address for reports and tell everyone about it.",
        pass_description="There is a process for reporting suspicious emails.",
    ),
    # ---------------- Incident response ----------------
    Question(
        id="ir_plan",
        section="Incident response",
        text="Does the business have a plan for what to do after a cyber incident?",
        help="Even one page covering who does what is better than none.",
        category=Category.BUSINESS_PRACTICES,
        severity=Severity.MEDIUM,
        effort=Effort.MEDIUM,
        issue_title="No incident response plan",
        issue_description="The business has no plan for responding to a cyber incident.",
        business_impact="Without a plan, the first hours after an incident are spent confused, which usually makes the damage and cost larger.",
        recommendation="Write a one-page plan covering who to call, what to disconnect, and how to restore from backup.",
        pass_description="An incident response plan exists.",
    ),
    Question(
        id="ir_contacts",
        section="Incident response",
        text="Does the business know who to contact after a cyber incident (IT support, insurer, authorities)?",
        help="Having these numbers written down saves time when it matters.",
        category=Category.BUSINESS_PRACTICES,
        severity=Severity.LOW,
        effort=Effort.LOW,
        issue_title="Incident contacts are not defined",
        issue_description="The business has not identified who to contact after a cyber incident.",
        business_impact="Delays in reaching help or reporting an incident can increase the damage and legal exposure.",
        recommendation="Write down contacts for IT support, your cyber insurer if any, and the relevant reporting authority.",
        pass_description="Incident contacts are known.",
    ),
]

_BY_ID = {q.id: q for q in QUESTIONS}


def public_questions() -> list[dict]:
    """What the frontend needs to render the form (no scoring details)."""
    return [
        {
            "id": q.id,
            "section": q.section,
            "text": q.text,
            "help": q.help,
            "depends_on": q.depends_on,
        }
        for q in QUESTIONS
    ]


def validate_answers(answers: dict[str, str]) -> None:
    """Raise ValueError for unknown question ids or invalid answers."""
    for qid, value in answers.items():
        if qid not in _BY_ID:
            raise ValueError(f"Unknown question: {qid}")
        if value not in VALID_ANSWERS:
            raise ValueError(f"Invalid answer for {qid}: {value}")


def evaluate_answers(answers: dict[str, str]) -> list[Finding]:
    """Turn questionnaire answers into standardized findings."""
    findings: list[Finding] = []
    for q in QUESTIONS:
        answer = answers.get(q.id)
        if answer is None:
            continue
        if q.depends_on and answers.get(q.depends_on) != "yes":
            continue

        finding_id = f"q_{q.id}"
        if answer == "yes":
            findings.append(make_pass(
                finding_id, q.pass_description, q.category,
                q.pass_description, evidence={"answer": answer},
            ))
            continue

        description = q.issue_description
        if answer == "unsure":
            description += " You answered 'not sure', so this could not be confirmed."
        findings.append(Finding(
            id=finding_id,
            title=q.issue_title,
            category=q.category,
            severity=q.severity,
            status=FindingStatus.ISSUE,
            description=description,
            business_impact=q.business_impact,
            recommendation=q.recommendation,
            effort=q.effort,
            evidence={"answer": answer},
        ))
    return findings
