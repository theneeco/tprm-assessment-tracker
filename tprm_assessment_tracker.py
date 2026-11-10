#!/usr/bin/env python3
"""
tprm_assessment_tracker.py  (Phase 2)

Third-party risk management workflow: request -> chase -> receive -> score ->
human decision -> reassessment clock resets.

Commands
--------
  run       Daily job (cron / Task Scheduler). Sends new assessment requests,
            reminders and final notices, and escalates non-responders
            internally. Running with no command = `run` (Phase 1 compatible).
  receive   Register a returned questionnaire: safety-checks the file, files it
            as evidence with a SHA-256 hash, scores it, writes a review summary.
  review    Record a named reviewer's decision (approve / approve-with-conditions
            / reject / request-info). Only an approval resets the vendor's
            reassessment clock.
  digest    Email the security lead a summary of everything needing attention.
  status    Print the current state of every vendor.
  verify-log  Check the audit log's hash chain has not been altered.

Lifecycle
---------
  Not Due / Approved / Approved with Conditions
      -- reassessment due within lookahead --> Requested        (vendor emailed)
  Requested          -- response deadline passes --> Reminder Sent      (vendor emailed)
  Reminder Sent      -- deadline passes --> Final Notice Sent           (vendor emailed)
  Final Notice Sent  -- deadline passes --> Escalated                   (business owner + security lead)
  Escalated          -- repeats internal escalation every N days until resolved
  any awaiting state -- `receive` --> Under Review  (or Received (Manual Review) if unparseable)
  Under Review       -- `review` --> Approved / Approved with Conditions / Rejected / Requested

Evidence for ISO 27001 A.5.19-A.5.22: the hash-chained audit log, the
evidence/ folder (response files + review summaries) and the register.

Usage
-----
  python tprm_assessment_tracker.py run --dry-run
  python tprm_assessment_tracker.py run --as-of-date 2026-10-20
  python tprm_assessment_tracker.py receive --vendor V001 --file ~/Downloads/acme.xlsx
  python tprm_assessment_tracker.py review --vendor V001 --decision approve --reviewer "J. Smith"
  python tprm_assessment_tracker.py status
"""

from __future__ import annotations

import argparse
import csv
import getpass
import hashlib
import json
import logging
import os
import re
import shutil
import smtplib
import sys
from datetime import date, datetime, timedelta
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# --------------------------------------------------------------------------
# .env loading (unchanged from Phase 1)
# --------------------------------------------------------------------------
try:
    from dotenv import load_dotenv
    load_dotenv(BASE_DIR / ".env")
except ImportError:
    env_path = BASE_DIR / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())

# ==========================================================================
# Configuration
# ==========================================================================

DEFAULT_REGISTER_PATH = Path(os.environ.get("TPRM_REGISTER_PATH", BASE_DIR / "vendors_register.csv"))
AUDIT_LOG_PATH = BASE_DIR / "tprm_audit_log.csv"
EVIDENCE_DIR = BASE_DIR / "evidence"
OUTBOX_DIR = BASE_DIR / "outbox"
DATE_FMT = "%Y-%m-%d"

# --- Reassessment cadence by tier (single source of truth, as in Phase 1) --
TIER_REASSESSMENT_FREQUENCY_DAYS = {"Critical": 182, "High": 182, "Medium": 365, "Low": 365}
DEFAULT_FREQUENCY_DAYS = 365

# --- Questionnaire by tier (fails safe to FULL) ----------------------------
TIER_QUESTIONNAIRE_MAP = {
    "Critical": BASE_DIR / "vendor_security_questionnaire_full.xlsx",
    "High": BASE_DIR / "vendor_security_questionnaire_full.xlsx",
    "Medium": BASE_DIR / "vendor_security_questionnaire_lite.xlsx",
    "Low": BASE_DIR / "vendor_security_questionnaire_lite.xlsx",
}
DEFAULT_QUESTIONNAIRE_PATH = BASE_DIR / "vendor_security_questionnaire_full.xlsx"

# --- Chasing and escalation -------------------------------------------------
RESPONSE_DEADLINE_DAYS = 14      # initial request: time to respond
REMINDER_DEADLINE_DAYS = 7       # each reminder / final notice extends by this
INFO_REQUEST_DEADLINE_DAYS = 7   # reviewer asks for more info
ESCALATION_REPEAT_DAYS = 14      # re-escalate internally this often while unresolved
REVIEW_SLA_DAYS = 10             # flag responses sitting unreviewed longer than this

# --- Email -----------------------------------------------------------------
SMTP_HOST = os.environ.get("TPRM_SMTP_HOST", "smtp.example.com")
SMTP_PORT = int(os.environ.get("TPRM_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("TPRM_SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("TPRM_SMTP_PASSWORD", "")
SENDER_NAME = os.environ.get("TPRM_SENDER_NAME", "Vendor Risk Management")
SENDER_EMAIL = os.environ.get("TPRM_SENDER_EMAIL", SMTP_USER)
SECURITY_LEAD_EMAIL = os.environ.get("TPRM_SECURITY_LEAD_EMAIL", "")
# "smtp" sends for real. "outbox" writes .eml files to ./outbox instead -- use
# it for UAT so you can open and check every email before going live.
EMAIL_MODE = os.environ.get("TPRM_EMAIL_MODE", "smtp").strip().lower()

# --- Statuses ---------------------------------------------------------------
NOT_DUE = "Not Due"
REQUESTED = "Requested"
REMINDED = "Reminder Sent"
FINAL = "Final Notice Sent"
ESCALATED = "Escalated"
UNDER_REVIEW = "Under Review"
RECEIVED_MANUAL = "Received (Manual Review)"
APPROVED = "Approved"
APPROVED_COND = "Approved with Conditions"
REJECTED = "Rejected"

IDLE_STATES = {NOT_DUE, APPROVED, APPROVED_COND}
AWAITING_STATES = {REQUESTED, REMINDED, FINAL, ESCALATED}
REVIEW_STATES = {UNDER_REVIEW, RECEIVED_MANUAL}
ALL_STATES = IDLE_STATES | AWAITING_STATES | REVIEW_STATES | {REJECTED}
LEGACY_STATUS_MAP = {"": NOT_DUE, "Not Due": NOT_DUE, "Assessment Requested": REQUESTED}

REGISTER_COLUMNS = [
    "vendor_id", "vendor_name", "contact_email", "risk_tier", "business_owner_email",
    "last_assessment_date", "status",
    # current request cycle
    "request_sent_date", "response_due_date", "reminder_count", "last_reminder_sent_date",
    "last_escalation_date",
    # response + scoring
    "response_received_date", "response_file", "response_sha256",
    "score", "residual_rating", "red_flags",
    # decision
    "review_decision", "reviewer", "review_date", "conditions", "conditions_due_date",
]
CYCLE_FIELDS = ["request_sent_date", "response_due_date", "reminder_count", "last_escalation_date"]
RESPONSE_FIELDS = ["response_received_date", "response_file", "response_sha256",
                   "score", "residual_rating", "red_flags",
                   "review_decision", "reviewer", "review_date"]

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.StreamHandler(sys.stdout)])
log = logging.getLogger("tprm")


# ==========================================================================
# Helpers
# ==========================================================================

def parse_date(value) -> date | None:
    value = (value or "").strip()
    return datetime.strptime(value, DATE_FMT).date() if value else None


def fmt(d: date | None) -> str:
    return d.strftime(DATE_FMT) if d else ""


def human_date(d: date) -> str:
    return d.strftime("%d %B %Y")


def next_due_date(vendor: dict, today: date) -> date:
    last = parse_date(vendor.get("last_assessment_date"))
    tier = (vendor.get("risk_tier") or "").strip()
    freq = TIER_REASSESSMENT_FREQUENCY_DAYS.get(tier, DEFAULT_FREQUENCY_DAYS)
    return today if last is None else last + timedelta(days=freq)


def questionnaire_for(vendor: dict) -> Path:
    tier = (vendor.get("risk_tier") or "").strip()
    return TIER_QUESTIONNAIRE_MAP.get(tier, DEFAULT_QUESTIONNAIRE_PATH)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ==========================================================================
# Register I/O (with migration from Phase 1 and safe writes)
# ==========================================================================

def load_register(path: Path) -> list[dict]:
    if not path.exists():
        raise FileNotFoundError(f"Vendor register not found at {path}")
    with open(path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))

    migrated = 0
    for v in rows:
        for col in REGISTER_COLUMNS:
            v.setdefault(col, "")
            if v[col] is None:
                v[col] = ""
        old = v["status"].strip()
        if old in LEGACY_STATUS_MAP:
            new = LEGACY_STATUS_MAP[old]
            if new != old:
                migrated += 1
            v["status"] = new
            # Phase 1 "Assessment Requested" -> reconstruct the request cycle
            if new == REQUESTED and not v["request_sent_date"]:
                sent = parse_date(v["last_reminder_sent_date"])
                if sent:
                    v["request_sent_date"] = fmt(sent)
                    v["response_due_date"] = fmt(sent + timedelta(days=RESPONSE_DEADLINE_DAYS))
                    v["reminder_count"] = "0"
        elif old not in ALL_STATES:
            log.warning("Vendor %s has unknown status '%s' -- treating as Not Due", v["vendor_id"], old)
            v["status"] = NOT_DUE
    if migrated:
        log.info("Migrated %d vendor status value(s) from Phase 1 format", migrated)
    return rows


def save_register(path: Path, vendors: list[dict]) -> None:
    """Backup, write to a temp file, then atomically replace. A crash mid-write
    can no longer leave you with a half-written register."""
    extra = [k for k in vendors[0].keys() if k not in REGISTER_COLUMNS] if vendors else []
    fieldnames = REGISTER_COLUMNS + extra  # keep any custom columns you've added
    if path.exists():
        shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(vendors)
    os.replace(tmp, path)


def find_vendor(vendors: list[dict], vendor_id: str) -> dict:
    for v in vendors:
        if v["vendor_id"].strip().lower() == vendor_id.strip().lower():
            return v
    raise SystemExit(f"Vendor '{vendor_id}' not found in register")


# ==========================================================================
# Hash-chained audit log
# ==========================================================================

LOG_FIELDS = ["timestamp", "command", "actor", "vendor_id", "vendor_name", "action",
              "from_status", "to_status", "detail", "prev_hash", "row_hash"]
GENESIS_HASH = "0" * 64


def _row_hash(row: dict) -> str:
    payload = {k: row[k] for k in LOG_FIELDS if k != "row_hash"}
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def _last_hash() -> str:
    if not AUDIT_LOG_PATH.exists():
        return GENESIS_HASH
    last = None
    with open(AUDIT_LOG_PATH, newline="", encoding="utf-8") as f:
        for last in csv.DictReader(f):
            pass
    return last["row_hash"] if last else GENESIS_HASH


class AuditLog:
    """Each row carries the hash of the previous row, so editing or deleting
    any historical row breaks the chain and `verify-log` will report it."""

    def __init__(self, command: str, dry_run: bool = False):
        self.command, self.dry_run = command, dry_run
        self.actor = getpass.getuser()
        self.rows: list[dict] = []

    def add(self, vendor: dict | None, action: str, from_status="", to_status="", detail=""):
        self.rows.append({
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "command": self.command, "actor": self.actor,
            "vendor_id": vendor["vendor_id"] if vendor else "",
            "vendor_name": vendor["vendor_name"] if vendor else "",
            "action": action, "from_status": from_status, "to_status": to_status,
            "detail": detail,
        })

    def flush(self):
        if self.dry_run or not self.rows:
            return
        prev = _last_hash()
        new_file = not AUDIT_LOG_PATH.exists()
        with open(AUDIT_LOG_PATH, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=LOG_FIELDS)
            if new_file:
                w.writeheader()
            for row in self.rows:
                row["prev_hash"] = prev
                row["row_hash"] = _row_hash(row)
                prev = row["row_hash"]
                w.writerow(row)
        self.rows = []


def cmd_verify_log(args) -> int:
    if not AUDIT_LOG_PATH.exists():
        print("No audit log yet.")
        return 0
    prev, n = GENESIS_HASH, 0
    with open(AUDIT_LOG_PATH, newline="", encoding="utf-8") as f:
        for n, row in enumerate(csv.DictReader(f), start=1):
            if row["prev_hash"] != prev or _row_hash(row) != row["row_hash"]:
                print(f"CHAIN BROKEN at row {n} ({row.get('timestamp')}, {row.get('vendor_id')}). "
                      f"The log has been altered at or before this row.")
                return 1
            prev = row["row_hash"]
    print(f"OK: {n} rows verified. Chain head: {prev}")
    print("Tip: store the chain head somewhere separate (e.g. monthly, in your ISMS "
          "records) -- that lets you prove the whole log wasn't regenerated.")
    return 0


# ==========================================================================
# Email
# ==========================================================================

def _attach_questionnaire(msg: MIMEMultipart, vendor: dict) -> None:
    path = questionnaire_for(vendor)
    if not path.exists():
        # FAIL CLOSED (Phase 1 sent the email without the attachment).
        raise FileNotFoundError(
            f"Questionnaire '{path.name}' for tier '{vendor.get('risk_tier')}' not found. "
            f"Email NOT sent.")
    with open(path, "rb") as f:
        part = MIMEApplication(f.read(), Name=path.name)
    part["Content-Disposition"] = f'attachment; filename="{path.name}"'
    msg.attach(part)


def _new_msg(to: list[str], subject: str, body: str, cc: list[str] | None = None) -> MIMEMultipart:
    msg = MIMEMultipart()
    msg["From"] = f"{SENDER_NAME} <{SENDER_EMAIL}>"
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))
    return msg


def _ref(vendor) -> str:
    # Stable reference in every subject line -- lets replies be matched to a
    # vendor later (useful if you automate mailbox intake).
    return f"[TPRM-{vendor['vendor_id']}]"


def vendor_email(kind: str, vendor: dict, deadline: date, notes: str = "") -> MIMEMultipart:
    name, tier = vendor["vendor_name"], vendor["risk_tier"]
    dl = human_date(deadline)
    if kind == "request":
        subject = f"Action Required: Security Assessment {_ref(vendor)} {name}"
        opening = ("As part of our third-party risk management program, your organisation is due "
                   "for its periodic security assessment.\n\n"
                   f"Please complete the attached questionnaire and return it by {dl}.")
    elif kind == "reminder":
        subject = f"Reminder: Security Assessment Overdue {_ref(vendor)} {name}"
        opening = ("We have not yet received your completed security questionnaire. The original "
                   f"deadline has passed. Please return it by {dl}.")
    elif kind == "final":
        subject = f"FINAL NOTICE: Security Assessment {_ref(vendor)} {name}"
        opening = ("This is a final notice. We have sent two previous requests for your security "
                   f"questionnaire. If we do not receive it by {dl}, the matter will be escalated "
                   "internally to your account relationship owner and may affect our ongoing use "
                   "of your services.")
    elif kind == "info":
        subject = f"Further Information Required: Security Assessment {_ref(vendor)} {name}"
        opening = ("Thank you for your questionnaire. Our review needs the following before it "
                   f"can be completed:\n\n{notes}\n\nPlease reply with this information by {dl}.")
    else:
        raise ValueError(kind)

    body = (f"Hello {name} team,\n\n{opening}\n\n"
            f"Vendor: {name}\nRisk tier: {tier}\nResponse deadline: {dl}\n\n"
            "Please return the questionnaire as a standard .xlsx file (not macro-enabled) and keep "
            f"the reference {_ref(vendor)} in the subject line of your reply.\n\n"
            f"If you have questions or need more time, reply to this email.\n\n"
            f"Thank you,\n{SENDER_NAME}\n")
    msg = _new_msg([vendor["contact_email"]], subject, body)
    if kind != "info":
        _attach_questionnaire(msg, vendor)
    return msg


def escalation_email(vendor: dict, today: date, repeat: bool) -> MIMEMultipart:
    owner = (vendor.get("business_owner_email") or "").strip()
    to = [owner] if owner else [SECURITY_LEAD_EMAIL]
    cc = [SECURITY_LEAD_EMAIL] if owner and SECURITY_LEAD_EMAIL else []
    requested = parse_date(vendor.get("request_sent_date"))
    days = (today - requested).days if requested else "unknown"
    overdue = (today - next_due_date(vendor, today)).days
    subject = (f"{'Repeat ' if repeat else ''}Escalation: Vendor not responding to security "
               f"assessment {_ref(vendor)} {vendor['vendor_name']}")
    body = (
        "Hello,\n\n"
        f"{vendor['vendor_name']} ({vendor['risk_tier']} risk) has not returned its security "
        f"questionnaire despite an initial request, a reminder and a final notice.\n\n"
        f"First requested: {fmt(requested) or 'unknown'} ({days} days ago)\n"
        f"Last completed assessment: {vendor.get('last_assessment_date') or 'never'}\n"
        f"Reassessment {'overdue by ' + str(overdue) + ' days' if overdue > 0 else 'due'}\n"
        f"Vendor contact: {vendor['contact_email']}\n\n"
        "As the business owner of this relationship, please contact the vendor directly to obtain "
        "the completed questionnaire. If the vendor will not engage, a decision is needed on "
        "whether to accept the risk, restrict their access, or exit the relationship.\n\n"
        + ("" if owner else "NOTE: no business_owner_email is recorded for this vendor in the "
                            "register. Please assign one.\n\n")
        + f"This escalation repeats every {ESCALATION_REPEAT_DAYS} days until resolved.\n\n"
        f"{SENDER_NAME}\n")
    return _new_msg(to, subject, body, cc)


def send(msg: MIMEMultipart, dry_run: bool) -> None:
    recipients = [a.strip() for h in ("To", "Cc") if msg[h] for a in msg[h].split(",") if a.strip()]
    if not recipients:
        raise ValueError("No recipients (check contact_email / TPRM_SECURITY_LEAD_EMAIL)")
    if dry_run:
        log.info("      [DRY RUN] would email %s | %s", ", ".join(recipients), msg["Subject"])
        return
    if EMAIL_MODE == "outbox":
        OUTBOX_DIR.mkdir(exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", recipients[0])
        out = OUTBOX_DIR / f"{datetime.now():%Y%m%d_%H%M%S_%f}_{safe}.eml"
        out.write_bytes(msg.as_bytes())
        log.info("      [OUTBOX] %s", out.name)
        return
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)


# ==========================================================================
# run: the daily state machine
# ==========================================================================

def _start_cycle(v: dict, today: date) -> None:
    for f in CYCLE_FIELDS + RESPONSE_FIELDS:
        v[f] = ""
    v["request_sent_date"] = fmt(today)
    v["response_due_date"] = fmt(today + timedelta(days=RESPONSE_DEADLINE_DAYS))
    v["reminder_count"] = "0"
    v["last_reminder_sent_date"] = fmt(today)


def process_vendor(v: dict, today: date, lookahead: int, dry_run: bool, audit: AuditLog) -> str:
    """Advance one vendor through the state machine. Returns an outcome label."""
    status = v["status"]

    # ---- Idle: is a reassessment due? ------------------------------------
    if status in IDLE_STATES:
        due = next_due_date(v, today)
        days = (due - today).days
        if days > lookahead:
            audit.add(v, "skipped", status, status, f"not due (due {fmt(due)}, {days}d away)")
            return "skipped"
        reason = f"OVERDUE by {-days}d (due {fmt(due)})" if days < 0 else f"due {fmt(due)} ({days}d)"
        deadline = today + timedelta(days=RESPONSE_DEADLINE_DAYS)
        log.info("SEND    %-28s request -- %s", v["vendor_name"], reason)
        send(vendor_email("request", v, deadline), dry_run)
        if not dry_run:
            _start_cycle(v, today)
            v["status"] = REQUESTED
        audit.add(v, "request_sent", status, REQUESTED, reason)
        return "sent"

    # ---- Awaiting the vendor: chase or escalate --------------------------
    if status in AWAITING_STATES:
        resp_due = parse_date(v["response_due_date"])
        if resp_due is None:  # repair a row edited by hand
            resp_due = today
            v["response_due_date"] = fmt(today)

        if status == ESCALATED:
            last_esc = parse_date(v["last_escalation_date"]) or today - timedelta(days=ESCALATION_REPEAT_DAYS)
            since = (today - last_esc).days
            if since < ESCALATION_REPEAT_DAYS:
                audit.add(v, "skipped", status, status, f"escalated {since}d ago; repeats every {ESCALATION_REPEAT_DAYS}d")
                return "skipped"
            log.info("ESCALATE %-27s repeat internal escalation", v["vendor_name"])
            send(escalation_email(v, today, repeat=True), dry_run)
            if not dry_run:
                v["last_escalation_date"] = fmt(today)
            audit.add(v, "escalation_repeated", status, status, f"{since}d since last escalation")
            return "escalated"

        if today < resp_due:
            audit.add(v, "skipped", status, status, f"awaiting response, due {fmt(resp_due)}")
            return "skipped"

        new_deadline = today + timedelta(days=REMINDER_DEADLINE_DAYS)
        if status == REQUESTED:
            kind, new_status, action = "reminder", REMINDED, "reminder_sent"
        elif status == REMINDED:
            kind, new_status, action = "final", FINAL, "final_notice_sent"
        else:  # FINAL -> escalate internally
            log.info("ESCALATE %-27s no response after final notice", v["vendor_name"])
            send(escalation_email(v, today, repeat=False), dry_run)
            if not dry_run:
                v["status"] = ESCALATED
                v["last_escalation_date"] = fmt(today)
            audit.add(v, "escalated", status, ESCALATED,
                      f"no response after final notice (deadline {fmt(resp_due)})")
            return "escalated"

        log.info("SEND    %-28s %s -- deadline %s passed", v["vendor_name"], kind, fmt(resp_due))
        send(vendor_email(kind, v, new_deadline), dry_run)
        if not dry_run:
            v["status"] = new_status
            v["response_due_date"] = fmt(new_deadline)
            v["reminder_count"] = str(int(v["reminder_count"] or 0) + 1)
            v["last_reminder_sent_date"] = fmt(today)
        audit.add(v, action, status, new_status, f"deadline {fmt(resp_due)} passed; new deadline {fmt(new_deadline)}")
        return "sent"

    # ---- With us: nothing to send the vendor -----------------------------
    if status in REVIEW_STATES:
        received = parse_date(v["response_received_date"])
        age = (today - received).days if received else 0
        note = f"awaiting internal review ({age}d)"
        if age > REVIEW_SLA_DAYS:
            note += f" -- EXCEEDS {REVIEW_SLA_DAYS}d review SLA"
            log.warning("REVIEW  %-28s %s", v["vendor_name"], note)
        audit.add(v, "skipped", status, status, note)
        return "skipped"

    if status == REJECTED:
        audit.add(v, "skipped", status, status, "rejected -- no automatic reassessment; offboarding decision required")
        return "skipped"

    return "skipped"


def cmd_run(args) -> int:
    today = parse_date(args.as_of_date) if args.as_of_date else date.today()
    log.info("TPRM run -- today=%s lookahead=%sd dry_run=%s email_mode=%s",
             today, args.lookahead_days, args.dry_run, EMAIL_MODE)
    vendors = load_register(args.register)
    audit = AuditLog("run", args.dry_run)
    counts = {"sent": 0, "escalated": 0, "skipped": 0, "failed": 0}

    for v in vendors:
        try:
            counts[process_vendor(v, today, args.lookahead_days, args.dry_run, audit)] += 1
        except Exception as exc:  # noqa: BLE001 -- one vendor must not kill the batch
            counts["failed"] += 1
            log.error("FAILED  %-28s %s", v["vendor_name"], exc)
            audit.add(v, "failed", v["status"], v["status"], str(exc))

    if not args.dry_run:
        save_register(args.register, vendors)
    audit.flush()
    log.info("Run complete: %(sent)s sent, %(escalated)s escalated, %(skipped)s skipped, %(failed)s failed", counts)

    if args.digest:
        send_digest(vendors, today, args.dry_run)
    return 1 if counts["failed"] else 0


# ==========================================================================
# receive: file, hash and score a returned questionnaire
# ==========================================================================

def cmd_receive(args) -> int:
    from tprm_scoring import QuestionnaireError, render_review_summary, score_questionnaire, validate_file

    today = parse_date(args.as_of_date) if args.as_of_date else date.today()
    vendors = load_register(args.register)
    v = find_vendor(vendors, args.vendor)
    src = Path(args.file).expanduser().resolve()
    audit = AuditLog("receive")
    old = v["status"]

    if old not in AWAITING_STATES:
        log.warning("%s is '%s', not awaiting a response. Recording anyway.", v["vendor_name"], old)

    # 1. Hygiene checks on the untrusted file -- reject outright on failure
    try:
        validate_file(src)
    except QuestionnaireError as exc:
        audit.add(v, "response_rejected", old, old, f"{src.name}: {exc}")
        audit.flush()
        log.error("REJECTED file for %s: %s", v["vendor_name"], exc)
        return 1

    # 2. File as evidence (never overwrite) and hash
    dest_dir = EVIDENCE_DIR / v["vendor_id"] / fmt(today)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{v['vendor_id']}_response_{fmt(today)}.xlsx"
    n = 1
    while dest.exists():
        n += 1
        dest = dest_dir / f"{v['vendor_id']}_response_{fmt(today)}_{n}.xlsx"
    shutil.copy2(src, dest)
    digest = sha256_file(dest)
    rel = dest.relative_to(BASE_DIR).as_posix()

    v["response_received_date"] = fmt(today)
    v["response_file"] = rel
    v["response_sha256"] = digest
    for f in ("score", "residual_rating", "red_flags", "review_decision", "reviewer", "review_date"):
        v[f] = ""

    # 3. Score
    summary_path = dest.with_name(dest.stem + "_review_summary.md")
    try:
        report = score_questionnaire(dest, today)
    except QuestionnaireError as exc:
        v["status"] = RECEIVED_MANUAL
        summary_path.write_text(
            f"# Vendor Security Review: {v['vendor_name']} ({v['vendor_id']})\n\n"
            f"- **Response file:** {dest.name}\n- **SHA-256:** `{digest}`\n\n"
            f"**Automatic scoring was not possible:** {exc}\n\n"
            "Review the file manually, then record a decision with `review`.\n\n"
            "## Decision\n\n_Pending._\n", encoding="utf-8")
        audit.add(v, "response_received_manual", old, RECEIVED_MANUAL, f"{rel} sha256={digest}; {exc}")
        save_register(args.register, vendors)
        audit.flush()
        log.warning("Stored %s but could not score it: %s", dest.name, exc)
        log.info("Summary: %s", summary_path)
        return 0

    v["status"] = UNDER_REVIEW
    v["score"] = f"{report.score:g}"
    v["residual_rating"] = report.residual_rating
    v["red_flags"] = "; ".join(f.title for f in report.critical_findings)
    summary_path.write_text(render_review_summary(report, v, dest.name, digest, today), encoding="utf-8")

    audit.add(v, "response_received", old, UNDER_REVIEW,
              f"{rel} sha256={digest}; score={report.score:g}; rating={report.residual_rating}; "
              f"critical={len(report.critical_findings)}; complete={report.is_complete}")
    save_register(args.register, vendors)
    audit.flush()

    print(f"\n{v['vendor_name']}: score {report.score:g}/100, residual rating {report.residual_rating}")
    print(f"Recommendation: {report.recommendation}")
    if report.missing_required:
        print(f"Missing answers: {', '.join(report.missing_required)}")
    for f in report.findings:
        if f.severity in ("Critical", "High"):
            print(f"  [{f.severity}] {f.title}")
    print(f"Review summary: {summary_path}\n")
    return 0


# ==========================================================================
# review: record a human decision
# ==========================================================================

DECISIONS = {
    "approve": APPROVED,
    "approve-with-conditions": APPROVED_COND,
    "reject": REJECTED,
    "request-info": REQUESTED,
}


def _append_decision(v: dict, block: str) -> None:
    if not v.get("response_file"):
        return
    resp = BASE_DIR / v["response_file"]
    summary = resp.with_name(resp.stem + "_review_summary.md")
    if summary.exists():
        text = summary.read_text(encoding="utf-8")
        text = re.sub(r"_Pending[^\n]*_\n?", "", text)
        summary.write_text(text.rstrip() + "\n\n" + block + "\n", encoding="utf-8")


def cmd_review(args) -> int:
    today = parse_date(args.as_of_date) if args.as_of_date else date.today()
    vendors = load_register(args.register)
    v = find_vendor(vendors, args.vendor)
    old = v["status"]
    new = DECISIONS[args.decision]

    # ---- Guardrails --------------------------------------------------------
    if old not in REVIEW_STATES:
        raise SystemExit(f"{v['vendor_name']} is '{old}'. Decisions can only be recorded for "
                         f"vendors in {sorted(REVIEW_STATES)} (run `receive` first).")
    if args.decision in ("reject", "request-info") and not args.notes:
        raise SystemExit(f"--notes is required for {args.decision}")
    if args.decision == "approve-with-conditions" and not (args.conditions and args.conditions_due):
        raise SystemExit("--conditions and --conditions-due are required for approve-with-conditions")
    if args.decision.startswith("approve"):
        if v["red_flags"] and not args.accept_risk:
            raise SystemExit(
                "This response has knockout findings:\n  - " + v["red_flags"].replace("; ", "\n  - ")
                + "\nApproval requires --accept-risk \"<justification and risk owner>\".")
        if old == RECEIVED_MANUAL and not args.notes:
            raise SystemExit("This response was not auto-scored. --notes describing your manual review is required.")

    # ---- Apply -------------------------------------------------------------
    detail = f"decision={args.decision}; reviewer={args.reviewer}"
    if args.notes:
        detail += f"; notes={args.notes}"
    if args.accept_risk:
        detail += f"; RISK ACCEPTED: {args.accept_risk}"

    if args.decision == "request-info":
        deadline = today + timedelta(days=INFO_REQUEST_DEADLINE_DAYS)
        send(vendor_email("info", v, deadline, notes=args.notes), dry_run=False)
        v["status"] = REQUESTED
        v["response_due_date"] = fmt(deadline)
        v["reminder_count"] = "0"
        v["last_reminder_sent_date"] = fmt(today)
        v["response_received_date"] = ""   # response_file kept: prior evidence stays referenced
        detail += f"; new deadline {fmt(deadline)}"
    else:
        v["status"] = new
        v["review_decision"] = args.decision
        v["reviewer"] = args.reviewer
        v["review_date"] = fmt(today)
        if args.decision.startswith("approve"):
            # THIS is the only place the reassessment clock resets.
            v["last_assessment_date"] = fmt(today)
            for f in CYCLE_FIELDS:
                v[f] = ""
            v["conditions"] = args.conditions or ""
            v["conditions_due_date"] = args.conditions_due or ""
            detail += f"; next reassessment {fmt(next_due_date(v, today))}"
        if args.conditions:
            detail += f"; conditions={args.conditions} (due {args.conditions_due})"

    block_lines = [f"### Decision recorded {fmt(today)}", "",
                   f"- **Decision:** {args.decision}", f"- **Reviewer:** {args.reviewer}",
                   f"- **Recorded by (system user):** {getpass.getuser()}"]
    if args.notes:
        block_lines.append(f"- **Notes:** {args.notes}")
    if args.conditions:
        block_lines.append(f"- **Conditions:** {args.conditions} (due {args.conditions_due})")
    if args.accept_risk:
        block_lines.append(f"- **Risk acceptance:** {args.accept_risk}")
    _append_decision(v, "\n".join(block_lines))

    audit = AuditLog("review")
    audit.add(v, f"decision_{args.decision.replace('-', '_')}", old, v["status"], detail)
    save_register(args.register, vendors)
    audit.flush()
    print(f"{v['vendor_name']}: {old} -> {v['status']}")
    return 0


# ==========================================================================
# digest + status
# ==========================================================================

def attention_items(vendors: list[dict], today: date) -> dict[str, list[str]]:
    items: dict[str, list[str]] = {
        "Escalated (vendor not responding)": [],
        "Awaiting review beyond SLA": [],
        "Reassessment overdue": [],
        "Conditions past due": [],
        "Rejected (offboarding decision needed)": [],
        "Missing business owner": [],
    }
    for v in vendors:
        label = f"{v['vendor_id']} {v['vendor_name']} ({v['risk_tier']})"
        s = v["status"]
        if s == ESCALATED:
            items["Escalated (vendor not responding)"].append(f"{label}, first requested {v['request_sent_date']}")
        if s in REVIEW_STATES:
            rec = parse_date(v["response_received_date"])
            if rec and (today - rec).days > REVIEW_SLA_DAYS:
                items["Awaiting review beyond SLA"].append(f"{label}, received {fmt(rec)} ({(today - rec).days}d)")
        if s != REJECTED:
            overdue = (today - next_due_date(v, today)).days
            if overdue > 0:
                items["Reassessment overdue"].append(f"{label}, {overdue}d overdue, status {s}")
        if s == APPROVED_COND:
            cd = parse_date(v["conditions_due_date"])
            if cd and cd < today:
                items["Conditions past due"].append(f"{label}: {v['conditions']} (due {fmt(cd)})")
        if s == REJECTED:
            items["Rejected (offboarding decision needed)"].append(f"{label}, rejected {v['review_date']}")
        if not (v.get("business_owner_email") or "").strip():
            items["Missing business owner"].append(label)
    return {k: val for k, val in items.items() if val}


def send_digest(vendors: list[dict], today: date, dry_run: bool) -> None:
    if not SECURITY_LEAD_EMAIL:
        log.warning("TPRM_SECURITY_LEAD_EMAIL not set -- digest not sent")
        return
    items = attention_items(vendors, today)
    counts: dict[str, int] = {}
    for v in vendors:
        counts[v["status"]] = counts.get(v["status"], 0) + 1
    body = [f"TPRM digest for {human_date(today)}", "",
            "Vendors by status: " + ", ".join(f"{k}: {n}" for k, n in sorted(counts.items())), ""]
    if not items:
        body.append("Nothing needs attention.")
    for heading, lines in items.items():
        body += [f"{heading} ({len(lines)})", *[f"  - {x}" for x in lines], ""]
    msg = _new_msg([SECURITY_LEAD_EMAIL], f"TPRM digest: {sum(map(len, items.values()))} item(s) need attention",
                   "\n".join(body) + f"\n{SENDER_NAME}\n")
    send(msg, dry_run)
    audit = AuditLog("digest", dry_run)
    audit.add(None, "digest_sent", detail=f"{sum(map(len, items.values()))} attention items")
    audit.flush()


def cmd_digest(args) -> int:
    today = parse_date(args.as_of_date) if args.as_of_date else date.today()
    send_digest(load_register(args.register), today, args.dry_run)
    return 0


def cmd_status(args) -> int:
    today = parse_date(args.as_of_date) if args.as_of_date else date.today()
    vendors = load_register(args.register)
    hdr = f"{'ID':<6}{'Vendor':<28}{'Tier':<10}{'Status':<26}{'Next due':<12}{'Resp. due':<12}{'Score':<7}{'Rating':<8}"
    print(hdr)
    print("-" * len(hdr))
    for v in vendors:
        print(f"{v['vendor_id']:<6}{v['vendor_name'][:27]:<28}{v['risk_tier']:<10}{v['status']:<26}"
              f"{fmt(next_due_date(v, today)):<12}{v['response_due_date']:<12}{v['score']:<7}{v['residual_rating']:<8}")
    items = attention_items(vendors, today)
    if items:
        print("\nNeeds attention:")
        for heading, lines in items.items():
            print(f"  {heading}:")
            for x in lines:
                print(f"    - {x}")
    return 0


# ==========================================================================
# CLI
# ==========================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="TPRM assessment tracker (Phase 2)")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp, dry=True):
        sp.add_argument("--register", type=Path, default=DEFAULT_REGISTER_PATH)
        sp.add_argument("--as-of-date", default=None, help="Simulate running on this date (YYYY-MM-DD)")
        if dry:
            sp.add_argument("--dry-run", action="store_true", help="No emails, no register or log writes")

    r = sub.add_parser("run", help="Daily job: requests, reminders, escalations")
    common(r)
    r.add_argument("--lookahead-days", type=int, default=30)
    r.add_argument("--digest", action="store_true", help="Also email the security lead digest")
    r.set_defaults(func=cmd_run)

    rc = sub.add_parser("receive", help="Register and score a returned questionnaire")
    common(rc, dry=False)
    rc.add_argument("--vendor", required=True)
    rc.add_argument("--file", required=True)
    rc.set_defaults(func=cmd_receive)

    rv = sub.add_parser("review", help="Record a reviewer decision")
    common(rv, dry=False)
    rv.add_argument("--vendor", required=True)
    rv.add_argument("--decision", required=True, choices=list(DECISIONS))
    rv.add_argument("--reviewer", required=True, help="Name of the person making the decision")
    rv.add_argument("--notes", default="")
    rv.add_argument("--conditions", default="")
    rv.add_argument("--conditions-due", default="")
    rv.add_argument("--accept-risk", default="", help="Required to approve despite knockout findings")
    rv.set_defaults(func=cmd_review)

    d = sub.add_parser("digest", help="Email the security lead an attention summary")
    common(d)
    d.set_defaults(func=cmd_digest)

    s = sub.add_parser("status", help="Print vendor status table")
    common(s, dry=False)
    s.set_defaults(func=cmd_status)

    vl = sub.add_parser("verify-log", help="Verify the audit log hash chain")
    vl.set_defaults(func=cmd_verify_log)
    return p


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Phase 1 compatibility: `tprm_assessment_tracker.py --dry-run` still means `run --dry-run`
    if not argv or argv[0].startswith("-"):
        argv.insert(0, "run")
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
