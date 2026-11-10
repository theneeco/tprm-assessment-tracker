# TPRM Assessment Tracker

A deterministic third-party risk management tool that runs the full vendor
reassessment lifecycle: request, chase, receive, score, and a human decision
that resets the clock. Built to replace a manual, spreadsheet-driven TPRM
process with something that runs itself on a schedule and never lets a
vendor slip through unreviewed.

## What it does

Every vendor in the register moves through the same cycle. The script works
out which vendors are due for reassessment, emails them a security
questionnaire, chases politely on a deadline, escalates internally if the
vendor goes quiet, and scores whatever comes back. Only a named human's
approval resets the clock. A vendor is never marked as assessed just because
an email was sent.

```
Requested -> Reminder -> Final notice -> Escalated
 (Day 0)     (Day 14)      (Day 21)      (Day 28, repeats)

vendor replies at any point
        |
        v
  Receive and score (automatic)
        |
        v
  Reviewer decision (a named human)
        |
        v
Approved / Approved with conditions / Rejected / Request info
```

## Commands

| Command      | What it does                                                        | Changes anything? |
|--------------|----------------------------------------------------------------------|--------------------|
| `run`        | The daily job (cron / Task Scheduler runs this)                      | Yes |
| `receive`    | Checks, files, fingerprints and scores a returned questionnaire      | Yes |
| `review`     | Records a named reviewer's decision                                  | Yes |
| `digest`     | Emails the security lead the weekly attention list                  | Sends one email |
| `status`     | Table of every vendor and anything needing attention                 | No |
| `verify-log` | Checks the audit log's hash chain hasn't been altered                | No |

```bash
python3 tprm_assessment_tracker.py run --dry-run
python3 tprm_assessment_tracker.py run --as-of-date 2026-10-20
python3 tprm_assessment_tracker.py receive --vendor V001 --file ~/Downloads/response.xlsx
python3 tprm_assessment_tracker.py review --vendor V001 --decision approve --reviewer "Nikhil Kubsad"
python3 tprm_assessment_tracker.py status
```

Add `--as-of-date YYYY-MM-DD` to `run`, `status`, `receive` or `review` to
simulate a different day.

## Scoring engine

Returned questionnaires are matched by question label, not fixed cell
coordinates, because vendors insert rows and reformat sheets, and label
matching survives that where coordinate matching silently reads the wrong
cell. Eleven rules check certification, pen testing, encryption, MFA, data
location, access reviews, the security function, incidents, breach
notification, business continuity and subprocessors, each mapped to an ISO
27001:2022 Annex A reference so the reviewer sees *why*, not just a number.

Encryption not in place, MFA not enforced, or Defence-related data held
offshore are knockouts: any one of them forces a High rating regardless of
the overall score, and the vendor cannot be approved without an explicit,
recorded risk acceptance. The scoring engine never approves anything; it
produces a recommendation and a review summary, and a named human makes the
decision.

## Evidence and audit trail

A returned file is refused if it isn't a plain `.xlsx`, is over 10 MB,
contains macros, or links to other workbooks. An accepted file is copied
into `evidence/<vendor_id>/<date>/` and given a SHA-256 fingerprint so it can
later be proven unaltered; earlier files are never overwritten. Every action
(a request sent, a reminder, a reviewer's decision) is written to
`tprm_audit_log.csv` with a hash that chains to the row before it, so a
later edit or deletion is detectable with `verify-log`.

This mirrors ISO/IEC 27001:2022 A.5.19-A.5.22 (supplier relationships and
information security in the supply chain).

## Setup

```bash
pip install -r requirements.txt   # python-dotenv is the only real dependency
cp .env.example .env              # fill in your own mail settings
```

`TPRM_EMAIL_MODE=outbox` (the default) saves every email as a `.eml` file in
an `outbox/` folder instead of sending it, so you can test wording and
timing safely before switching to `smtp` for live operation.

To run it automatically on macOS, see the cron example in
`TPRM_How_It_Works.pdf`, which also walks through the full lifecycle day by
day, who gets emailed when, and every setting that controls timing.

## Status

This is a working tool, tested against the fictional vendor register
included here (`vendors_register.csv`), not yet run against a real
organisation's vendors. Vendor names, contacts and the org domain
(`yourorg.com.au`) throughout this repo are fictional.
