"""
tprm_scoring.py

Scoring engine for returned vendor security questionnaires.

Design principles
-----------------
* Answers are located by the QUESTION LABEL in column A, not by fixed cell
  coordinates. Vendors insert rows, unmerge cells and reformat sheets; label
  matching survives that, coordinate matching silently reads the wrong cell.
* Every rule returns points, a severity and a human-readable finding with an
  ISO 27001:2022 Annex A reference, so the reviewer sees WHY, not just a number.
* "Critical" findings are knockouts: the vendor cannot be approved without an
  explicit, recorded risk acceptance (see `review` in the tracker).
* The engine never approves anything. It produces a recommendation and a
  review summary; a named human makes the decision.

All thresholds and weights live in the CONFIG section below.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

# ==========================================================================
# CONFIG -- tune these to your risk appetite
# ==========================================================================

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # reject anything larger than 10 MB

# Score bands -> residual rating (applied only when there are no Critical findings)
RATING_BANDS = [(80, "Low"), (60, "Medium"), (0, "High")]

PENTEST_MAX_AGE_DAYS = 365          # full marks inside this
PENTEST_STALE_AGE_DAYS = 730        # partial marks up to this, zero beyond
BCP_TEST_MAX_AGE_DAYS = 365
BREACH_SLA_GOOD_HOURS = 24
BREACH_SLA_ACCEPTABLE_HOURS = 72

# Severity applied to offshore data storage. Escalated to Critical when the
# vendor says it handles Defence-related data (see DEFENCE_DATA_PATTERN).
OFFSHORE_SEVERITY_DEFAULT = "High"
OFFSHORE_SEVERITY_DEFENCE = "Critical"

AU_PATTERN = re.compile(
    r"\b(australia|australian|aus|au|sydney|melbourne|canberra|brisbane|perth|adelaide|"
    r"hobart|darwin|ap-southeast-2|ap-southeast-4|australia\s*(east|southeast|central))\b",
    re.IGNORECASE,
)
NON_AU_PATTERN = re.compile(
    r"\b(us|usa|united states|america|eu|europe|european|ireland|uk|united kingdom|"
    r"england|germany|france|netherlands|singapore|india|japan|china|hong kong|"
    r"canada|new zealand|nz|global|worldwide|multi-region|us-east|us-west|eu-west|"
    r"eu-central|ap-south|ap-northeast|ap-southeast-1)\b",
    re.IGNORECASE,
)
DEFENCE_DATA_PATTERN = re.compile(
    r"\b(defence|defense|classified|official:?\s*sensitive|protected|secret|"
    r"dlm|itar|export[- ]controlled|controlled technical|dsgl|security[- ]classified)\b",
    re.IGNORECASE,
)

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

# Question labels (lower-case prefixes of the column-A text). If you reword a
# question in the template, update its prefix here.
LABELS = {
    "company_name": "company name",
    "security_contact": "primary security contact",
    "contact_email": "contact email",
    "date_completed": "date completed",
    "iso_cert": "current iso/iec 27001 certification",
    "iso_expiry": "if yes, certificate expiry date",
    "soc2": "current soc 2 type ii",
    "other_certs": "other relevant certifications",
    "pentest": "do you undergo annual third-party penetration testing",
    "pentest_date": "date of most recent penetration test",
    "data_types": "what types of our data",
    "data_location": "where is data stored",
    "enc_rest": "is data encrypted at rest",
    "enc_transit": "is data encrypted in transit",
    "mfa": "is mfa enforced",
    "access_reviews": "do you conduct periodic user access reviews",
    "security_function": "do you have a dedicated security function",
    "breach": "security breach or data incident in the last 24 months",
    "breach_desc": "if yes, describe the incident",
    "breach_sla": "what is your breach notification sla",
    "bcp": "documented business continuity",
    "bcp_tested": "when was it last tested",
}

# Fields that must be answered for a response to count as complete.
# Conditional fields (expiry date, pen test date, breach description) are
# checked inside the relevant rules instead.
REQUIRED_FIELDS = [
    "company_name", "security_contact", "contact_email", "date_completed",
    "iso_cert", "soc2", "pentest", "data_types", "data_location",
    "enc_rest", "enc_transit", "mfa", "access_reviews", "security_function",
    "breach", "breach_sla", "bcp",
]

SUBPROCESSOR_HEADER = "subprocessor name"


# ==========================================================================
# Data structures
# ==========================================================================

@dataclass
class Finding:
    severity: str
    rule_id: str
    title: str
    detail: str
    control_ref: str


@dataclass
class RuleResult:
    rule_id: str
    title: str
    points: float
    max_points: float
    control_ref: str
    findings: list[Finding] = field(default_factory=list)
    excluded: bool = False  # question not present in this questionnaire variant


@dataclass
class ScoreReport:
    questionnaire_variant: str
    answers: dict
    subprocessors: list[dict]
    missing_required: list[str]
    rule_results: list[RuleResult]
    score: float
    residual_rating: str
    knockout: bool
    recommendation: str

    @property
    def findings(self) -> list[Finding]:
        out = [f for r in self.rule_results for f in r.findings]
        return sorted(out, key=lambda f: SEVERITY_ORDER.index(f.severity))

    @property
    def critical_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "Critical"]

    @property
    def is_complete(self) -> bool:
        return not self.missing_required


class QuestionnaireError(Exception):
    """Raised when a returned file cannot be safely parsed as our questionnaire."""


# ==========================================================================
# Safe file intake + parsing
# ==========================================================================

def validate_file(path: Path) -> None:
    """
    Basic hygiene on an untrusted file from a third party BEFORE parsing it.
    openpyxl never executes macros, but we still refuse anything that isn't a
    plain .xlsx so macro-enabled or legacy formats never enter the evidence store.
    """
    if not path.exists():
        raise QuestionnaireError(f"File not found: {path}")
    if path.suffix.lower() != ".xlsx":
        raise QuestionnaireError(
            f"Only .xlsx is accepted (got '{path.suffix}'). Ask the vendor to re-save "
            f"as a standard Excel workbook -- do not open macro-enabled files."
        )
    size = path.stat().st_size
    if size > MAX_FILE_SIZE_BYTES:
        raise QuestionnaireError(f"File is {size:,} bytes, over the {MAX_FILE_SIZE_BYTES:,} byte limit")
    if not zipfile.is_zipfile(path):
        raise QuestionnaireError("File is not a valid .xlsx container (not a zip archive)")
    with zipfile.ZipFile(path) as zf:
        names = [n.lower() for n in zf.namelist()]
        if any("vbaproject" in n for n in names):
            raise QuestionnaireError("File contains a VBA project (macros). Rejected.")
        if any(n.startswith("xl/externallinks/") for n in names):
            raise QuestionnaireError("File contains external workbook links. Rejected.")


def _norm(text) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip().lower()


def parse_questionnaire(path: Path) -> tuple[str, dict, list[dict], set[str]]:
    """
    Returns (variant, answers, subprocessors, labels_found).
    variant is "full" or "lite" (from the title in A1).
    """
    from openpyxl import load_workbook  # imported here so the tracker runs without it for `run`

    validate_file(path)
    try:
        wb = load_workbook(path, data_only=True)  # data_only: read values, never formulas
    except Exception as exc:  # noqa: BLE001
        raise QuestionnaireError(f"Could not open workbook: {exc}") from exc

    ws = wb.worksheets[0]
    title = _norm(ws["A1"].value)
    if "vendor security assessment questionnaire" not in title:
        raise QuestionnaireError(
            "This does not look like our questionnaire (title in A1 not recognised). "
            "The vendor may have sent their own format -- review manually."
        )
    variant = "lite" if "lite" in title else "full"

    answers: dict = {}
    labels_found: set[str] = set()
    subprocessors: list[dict] = []
    in_subprocessors = False

    for row in ws.iter_rows(min_row=1, max_col=4):
        a, b, c, d = (cell.value for cell in row[:4])
        label = _norm(a)

        # Section headers look like "G. Business Continuity" -- end any table
        if re.match(r"^[a-z]\.\s", label):
            in_subprocessors = False
            continue

        if label == SUBPROCESSOR_HEADER:
            in_subprocessors = True
            continue

        if in_subprocessors:
            if all(v in (None, "") for v in (a, b, c, d)):
                continue
            if "(example)" in label:
                continue
            subprocessors.append({
                "name": str(a or "").strip(), "purpose": str(b or "").strip(),
                "data": str(c or "").strip(), "location": str(d or "").strip(),
            })
            continue

        for key, prefix in LABELS.items():
            if key not in labels_found and label.startswith(prefix):
                labels_found.add(key)
                answers[key] = b
                break

    return variant, answers, subprocessors, labels_found


# ==========================================================================
# Value interpretation helpers
# ==========================================================================

def _blank(value) -> bool:
    return value is None or str(value).strip() == ""


def yes_no(value) -> str:
    """Normalise to 'yes' / 'no' / 'blank' / 'unclear'."""
    if _blank(value):
        return "blank"
    if isinstance(value, bool):
        return "yes" if value else "no"
    v = _norm(value)
    if re.match(r"^(yes|y|true|✓|enforced|in place)\b", v):
        return "yes"
    if re.match(r"^(no|n|false|not)\b", v):
        return "no"
    return "unclear"


DATE_FORMATS = [
    "%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y", "%d/%m/%y",
    "%d %B %Y", "%d %b %Y", "%B %d, %Y", "%b %d, %Y", "%B %Y", "%b %Y", "%m/%Y", "%Y",
]


def to_date(value) -> date | None:
    """Best-effort date parse. Australian day-first formats are tried before US."""
    if _blank(value):
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value).strip()
    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    return None


def to_hours(value) -> float | None:
    """'24', '72 hours', 'within 48h', '3 days', '1 business day' -> hours."""
    if _blank(value):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = _norm(value)
    m = re.search(r"(\d+(?:\.\d+)?)", text)
    if not m:
        return None
    n = float(m.group(1))
    if re.search(r"\bday", text):
        return n * 24
    if re.search(r"\bweek", text):
        return n * 24 * 7
    return n


def classify_location(text) -> str:
    """'au' / 'mixed' / 'offshore' / 'unclear'."""
    if _blank(text):
        return "unclear"
    has_au = bool(AU_PATTERN.search(str(text)))
    has_other = bool(NON_AU_PATTERN.search(str(text)))
    if has_au and not has_other:
        return "au"
    if has_au and has_other:
        return "mixed"
    if has_other:
        return "offshore"
    return "unclear"


# ==========================================================================
# Rules
# ==========================================================================

def _f(sev, rid, title, detail, ref) -> Finding:
    return Finding(sev, rid, title, detail, ref)


def rule_assurance(ans, today, ctx) -> RuleResult:
    rid, ref = "R01", "A.5.19, A.5.20"
    r = RuleResult(rid, "Independent security assurance (ISO 27001 / SOC 2)", 0, 15, ref)
    iso, soc2 = yes_no(ans.get("iso_cert")), yes_no(ans.get("soc2"))
    expiry = to_date(ans.get("iso_expiry"))

    if iso == "yes":
        if expiry is None:
            r.points = 10
            r.findings.append(_f("Low", rid, "ISO 27001 expiry date missing or unreadable",
                                 "Request a copy of the certificate and confirm scope and expiry.", ref))
        elif expiry < today:
            r.points = 0
            r.findings.append(_f("High", rid, "ISO 27001 certificate has expired",
                                 f"Stated expiry {expiry.isoformat()} is in the past.", ref))
        else:
            r.points = 15
            if (expiry - today).days < 90:
                r.findings.append(_f("Info", rid, "ISO 27001 certificate expires within 90 days",
                                     f"Expiry {expiry.isoformat()}. Diary a follow-up for the renewed certificate.", ref))
            r.findings.append(_f("Info", rid, "Confirm ISO 27001 certificate scope",
                                 "Check the certificate scope covers the services provided to you.", ref))
    elif soc2 == "yes":
        r.points = 12
        r.findings.append(_f("Info", rid, "SOC 2 Type II relied on instead of ISO 27001",
                             "Obtain the report under NDA and review exceptions and bridge letter.", ref))
    else:
        r.findings.append(_f("High", rid, "No independent security assurance",
                             "Neither ISO 27001 certification nor a SOC 2 Type II report was declared.", ref))
    return r


def rule_pentest(ans, today, ctx) -> RuleResult:
    rid, ref = "R02", "A.8.8, A.5.20"
    r = RuleResult(rid, "Independent penetration testing", 0, 10, ref)
    pt = yes_no(ans.get("pentest"))
    pt_date = to_date(ans.get("pentest_date"))

    if pt == "no":
        r.findings.append(_f("High", rid, "No annual third-party penetration testing", "", ref))
    elif pt in ("blank", "unclear"):
        r.findings.append(_f("Medium", rid, "Penetration testing answer missing or unclear",
                             f"Answer given: '{ans.get('pentest')}'.", ref))
    elif pt_date is None:
        r.points = 5
        r.findings.append(_f("Medium", rid, "Penetration test date not provided",
                             "Request the date and an executive summary of the most recent test.", ref))
    else:
        age = (today - pt_date).days
        if age <= PENTEST_MAX_AGE_DAYS:
            r.points = 10
        elif age <= PENTEST_STALE_AGE_DAYS:
            r.points = 5
            r.findings.append(_f("Medium", rid, "Penetration test older than 12 months",
                                 f"Last test {pt_date.isoformat()} ({age} days ago).", ref))
        else:
            r.findings.append(_f("High", rid, "Penetration test older than 24 months",
                                 f"Last test {pt_date.isoformat()} ({age} days ago).", ref))
    return r


def _encryption_rule(rid, key, label):
    ref = "A.8.24"

    def rule(ans, today, ctx) -> RuleResult:
        r = RuleResult(rid, f"Encryption {label}", 0, 10, ref)
        v = yes_no(ans.get(key))
        if v == "yes":
            r.points = 10
        elif v == "no":
            r.findings.append(_f("Critical", rid, f"Data NOT encrypted {label}",
                                 "Knockout: cannot be approved without recorded risk acceptance.", ref))
        else:
            r.findings.append(_f("Medium", rid, f"Encryption {label} answer missing or unclear",
                                 f"Answer given: '{ans.get(key)}'.", ref))
        return r
    return rule


def rule_mfa(ans, today, ctx) -> RuleResult:
    rid, ref = "R05", "A.5.17, A.8.5"
    r = RuleResult(rid, "MFA enforced for all staff", 0, 15, ref)
    v = yes_no(ans.get("mfa"))
    if v == "yes":
        r.points = 15
    elif v == "no":
        r.findings.append(_f("Critical", rid, "MFA not enforced for staff with system access",
                             "Knockout. MFA is an Essential Eight strategy; a supplier without it is a "
                             "direct credential-compromise path into data they hold for you.", ref))
    else:
        r.findings.append(_f("Medium", rid, "MFA answer missing or unclear",
                             f"Answer given: '{ans.get('mfa')}'.", ref))
    return r


def rule_data_location(ans, today, ctx) -> RuleResult:
    rid, ref = "R06", "A.5.20, A.5.23, A.5.34"
    r = RuleResult(rid, "Data residency (Australian hosting)", 0, 10, ref)
    loc = classify_location(ans.get("data_location"))
    defence = ctx["defence_data"]
    sev = OFFSHORE_SEVERITY_DEFENCE if defence else OFFSHORE_SEVERITY_DEFAULT
    extra = " Vendor indicates Defence-related data is in scope." if defence else ""

    if loc == "au":
        r.points = 10
    elif loc == "mixed":
        r.points = 5
        r.findings.append(_f(sev, rid, "Data partially stored offshore",
                             f"Stated location: '{ans.get('data_location')}'.{extra} Confirm which data "
                             f"leaves Australia and whether this is permitted under your contracts.", ref))
    elif loc == "offshore":
        r.findings.append(_f(sev, rid, "Data stored offshore",
                             f"Stated location: '{ans.get('data_location')}'.{extra}", ref))
    else:
        r.findings.append(_f("Medium", rid, "Data location missing or unclear",
                             f"Answer given: '{ans.get('data_location')}'.", ref))
    return r


def rule_access_reviews(ans, today, ctx) -> RuleResult:
    rid, ref = "R07", "A.5.18"
    r = RuleResult(rid, "Periodic user access reviews", 0, 5, ref)
    raw = ans.get("access_reviews")
    v = yes_no(raw)
    text = _norm(raw)
    if v == "no":
        r.findings.append(_f("Medium", rid, "No periodic user access reviews", "", ref))
    elif _blank(raw):
        r.findings.append(_f("Medium", rid, "Access review answer missing", "", ref))
    elif re.search(r"month|quarter|6 month|six month|semi|bi-annual|biannual", text):
        r.points = 5
    elif re.search(r"annual|year", text):
        r.points = 3
        r.findings.append(_f("Low", rid, "Access reviews only annual",
                             "Consider requiring at least 6-monthly reviews for privileged access.", ref))
    else:
        r.points = 2
        r.findings.append(_f("Low", rid, "Access review frequency not stated",
                             f"Answer given: '{raw}'.", ref))
    return r


def rule_security_function(ans, today, ctx) -> RuleResult:
    rid, ref = "R08", "A.5.2"
    r = RuleResult(rid, "Dedicated security function / CISO", 0, 5, ref)
    v = yes_no(ans.get("security_function"))
    if v == "yes":
        r.points = 5
    else:
        r.findings.append(_f("Low", rid, "No dedicated security function declared",
                             f"Answer given: '{ans.get('security_function')}'.", ref))
    return r


def rule_incidents(ans, today, ctx) -> RuleResult:
    rid, ref = "R09", "A.5.24, A.5.26"
    r = RuleResult(rid, "Incident history (last 24 months)", 0, 5, ref)
    v = yes_no(ans.get("breach"))
    if v == "no":
        r.points = 5
    elif v == "yes":
        if _blank(ans.get("breach_desc")):
            r.findings.append(_f("High", rid, "Breach declared but no details or remediation given", "", ref))
        else:
            r.points = 2
            r.findings.append(_f("Medium", rid, "Security incident in last 24 months",
                                 "Review the description and confirm remediation is complete.", ref))
    else:
        r.findings.append(_f("Medium", rid, "Incident history answer missing or unclear", "", ref))
    return r


def rule_breach_sla(ans, today, ctx) -> RuleResult:
    rid, ref = "R10", "A.5.20, A.5.24"
    r = RuleResult(rid, "Breach notification SLA", 0, 10, ref)
    hours = to_hours(ans.get("breach_sla"))
    if hours is None:
        r.findings.append(_f("Medium", rid, "Breach notification SLA missing or unreadable",
                             f"Answer given: '{ans.get('breach_sla')}'.", ref))
    elif hours <= BREACH_SLA_GOOD_HOURS:
        r.points = 10
    elif hours <= BREACH_SLA_ACCEPTABLE_HOURS:
        r.points = 7
    else:
        r.findings.append(_f("High", rid, f"Breach notification SLA exceeds {BREACH_SLA_ACCEPTABLE_HOURS} hours",
                             f"Stated {hours:g} hours. This may not let you meet your own incident "
                             f"reporting obligations. Negotiate a contractual SLA.", ref))
    return r


def rule_bcp(ans, today, ctx) -> RuleResult:
    rid, ref = "R11", "A.5.29, A.5.30"
    r = RuleResult(rid, "Business continuity / DR", 0, 5, ref)
    v = yes_no(ans.get("bcp"))
    tested = to_date(ans.get("bcp_tested"))
    if v == "yes":
        if tested and (today - tested).days <= BCP_TEST_MAX_AGE_DAYS:
            r.points = 5
        else:
            r.points = 2
            r.findings.append(_f("Medium", rid, "BCP/DR not tested in last 12 months",
                                 f"Last tested: '{ans.get('bcp_tested') or 'not provided'}'.", ref))
    elif v == "no":
        r.findings.append(_f("High", rid, "No documented BCP/DR plan", "", ref))
    else:
        r.findings.append(_f("Medium", rid, "BCP/DR answer missing or unclear", "", ref))
    return r


def rule_subprocessors(ans, today, ctx) -> RuleResult:
    rid, ref = "R12", "A.5.19, A.5.21"
    r = RuleResult(rid, "Subprocessors (fourth parties)", 0, 0, ref)  # findings only, no points
    subs = ctx["subprocessors"]
    if not subs:
        r.findings.append(_f("Info", rid, "No subprocessors listed",
                             "Confirm in writing that no subprocessors access your data.", ref))
        return r
    sev = OFFSHORE_SEVERITY_DEFENCE if ctx["defence_data"] else "Medium"
    for s in subs:
        loc = classify_location(s["location"])
        if loc in ("offshore", "mixed"):
            r.findings.append(_f(sev, rid, f"Offshore subprocessor: {s['name']}",
                                 f"Location '{s['location']}', data: '{s['data']}'.", ref))
        elif loc == "unclear":
            r.findings.append(_f("Low", rid, f"Subprocessor location unclear: {s['name']}",
                                 f"Location given: '{s['location']}'.", ref))
    return r


# (rule function, answer keys it depends on)
RULES = [
    (rule_assurance, ["iso_cert", "soc2"]),
    (rule_pentest, ["pentest"]),
    (_encryption_rule("R03", "enc_rest", "at rest"), ["enc_rest"]),
    (_encryption_rule("R04", "enc_transit", "in transit"), ["enc_transit"]),
    (rule_mfa, ["mfa"]),
    (rule_data_location, ["data_location"]),
    (rule_access_reviews, ["access_reviews"]),
    (rule_security_function, ["security_function"]),
    (rule_incidents, ["breach"]),
    (rule_breach_sla, ["breach_sla"]),
    (rule_bcp, ["bcp"]),
    (rule_subprocessors, []),
]


# ==========================================================================
# Public entry point
# ==========================================================================

def score_questionnaire(path: Path, today: date) -> ScoreReport:
    variant, answers, subprocessors, labels_found = parse_questionnaire(path)

    missing_labels = [k for k in REQUIRED_FIELDS if k not in labels_found]
    if variant == "full" and missing_labels:
        # The full template must contain every question. If labels are gone the
        # vendor has edited the questions themselves -- don't guess.
        raise QuestionnaireError(
            "Questions missing or reworded in returned file: " + ", ".join(missing_labels)
            + ". The vendor may have altered the template -- review manually."
        )

    missing_required = [k for k in REQUIRED_FIELDS if k in labels_found and _blank(answers.get(k))]
    ctx = {
        "subprocessors": subprocessors,
        "defence_data": bool(DEFENCE_DATA_PATTERN.search(str(answers.get("data_types") or ""))),
    }

    results: list[RuleResult] = []
    for fn, deps in RULES:
        if deps and not all(k in labels_found for k in deps):
            # Question not in this variant (e.g. lite) -- exclude from the denominator
            res = fn({}, today, ctx)
            res.points, res.findings, res.excluded = 0, [], True
            results.append(res)
            continue
        results.append(fn(answers, today, ctx))

    possible = sum(r.max_points for r in results if not r.excluded)
    earned = sum(r.points for r in results if not r.excluded)
    score = round(100 * earned / possible, 1) if possible else 0.0

    knockout = any(f.severity == "Critical" for r in results for f in r.findings)
    if knockout:
        rating = "High"
    else:
        rating = next(label for threshold, label in RATING_BANDS if score >= threshold)

    if missing_required:
        recommendation = "Request missing information before deciding"
    elif knockout:
        recommendation = "Do not approve unless risk is formally accepted"
    elif rating == "Low":
        recommendation = "Approve"
    elif rating == "Medium":
        recommendation = "Approve with conditions"
    else:
        recommendation = "Escalate: approve only with conditions and risk owner sign-off"

    return ScoreReport(variant, answers, subprocessors, missing_required, results,
                       score, rating, knockout, recommendation)


def render_review_summary(report: ScoreReport, vendor: dict, file_name: str, sha256: str,
                          today: date) -> str:
    """Markdown summary the reviewer reads before recording a decision."""
    lines = [
        f"# Vendor Security Review: {vendor['vendor_name']} ({vendor['vendor_id']})",
        "",
        f"- **Risk tier:** {vendor.get('risk_tier', '')}",
        f"- **Questionnaire:** {report.questionnaire_variant}",
        f"- **Response file:** {file_name}",
        f"- **SHA-256:** `{sha256}`",
        f"- **Scored on:** {today.isoformat()}",
        f"- **Score:** {report.score} / 100",
        f"- **Residual rating:** {report.residual_rating}",
        f"- **Complete:** {'Yes' if report.is_complete else 'No'}",
        f"- **Knockout findings:** {len(report.critical_findings)}",
        f"- **Engine recommendation:** {report.recommendation}",
        "",
        "> The engine recommends; a named reviewer decides. Record the decision with "
        "`tprm_assessment_tracker.py review`.",
        "",
    ]
    if report.missing_required:
        lines += ["## Missing answers", ""]
        lines += [f"- {k}" for k in report.missing_required]
        lines.append("")

    lines += ["## Findings", ""]
    if report.findings:
        lines += ["| Severity | Rule | Finding | Detail | ISO 27001 ref |", "|---|---|---|---|---|"]
        for f in report.findings:
            detail = f.detail.replace("|", "/").replace("\n", " ")
            lines.append(f"| {f.severity} | {f.rule_id} | {f.title} | {detail} | {f.control_ref} |")
    else:
        lines.append("No findings.")
    lines.append("")

    lines += ["## Rule scores", "", "| Rule | Area | Points |", "|---|---|---|"]
    for r in report.rule_results:
        pts = "n/a (not asked)" if r.excluded else f"{r.points:g} / {r.max_points:g}"
        lines.append(f"| {r.rule_id} | {r.title} | {pts} |")
    lines.append("")

    lines += ["## Answers as submitted", "", "| Question | Answer |", "|---|---|"]
    for key in LABELS:
        if key in report.answers:
            val = str(report.answers[key] if report.answers[key] is not None else "").replace("|", "/").replace("\n", " ")
            lines.append(f"| {key} | {val} |")
    lines.append("")

    if report.subprocessors:
        lines += ["## Subprocessors", "", "| Name | Purpose | Data | Location |", "|---|---|---|---|"]
        for s in report.subprocessors:
            lines.append(f"| {s['name']} | {s['purpose']} | {s['data']} | {s['location']} |")
        lines.append("")

    lines += ["## Decision", "", "_Pending. Appended automatically when the decision is recorded._", ""]
    return "\n".join(lines)
