# Vendor Security Review: SecureVault Offsite Backup (V008)

- **Risk tier:** High
- **Questionnaire:** full
- **Response file:** V008_response_2026-11-10.xlsx
- **SHA-256:** `39fbcf76648e2d0f627883d1fd8fcdfba55d848bc1ec492d00da4a7445bcfecb`
- **Scored on:** 2026-11-10
- **Score:** 70.0 / 100
- **Residual rating:** High
- **Complete:** Yes
- **Knockout findings:** 1
- **Engine recommendation:** Do not approve unless risk is formally accepted

> The engine recommends; a named reviewer decides. Record the decision with `tprm_assessment_tracker.py review`.

## Findings

| Severity | Rule | Finding | Detail | ISO 27001 ref |
|---|---|---|---|---|
| Critical | R05 | MFA not enforced for staff with system access | Knockout. MFA is an Essential Eight strategy; a supplier without it is a direct credential-compromise path into data they hold for you. | A.5.17, A.8.5 |
| High | R06 | Data stored offshore | Stated location: 'United States (AWS us-east-1)'. | A.5.20, A.5.23, A.5.34 |
| Medium | R02 | Penetration test older than 12 months | Last test 2025-09-01 (435 days ago). | A.8.8, A.5.20 |
| Medium | R12 | Offshore subprocessor: ColdStore Infrastructure | Location 'Singapore', data: 'Encrypted backups only'. | A.5.19, A.5.21 |
| Info | R01 | Confirm ISO 27001 certificate scope | Check the certificate scope covers the services provided to you. | A.5.19, A.5.20 |

## Rule scores

| Rule | Area | Points |
|---|---|---|
| R01 | Independent security assurance (ISO 27001 / SOC 2) | 15 / 15 |
| R02 | Independent penetration testing | 5 / 10 |
| R03 | Encryption at rest | 10 / 10 |
| R04 | Encryption in transit | 10 / 10 |
| R05 | MFA enforced for all staff | 0 / 15 |
| R06 | Data residency (Australian hosting) | 0 / 10 |
| R07 | Periodic user access reviews | 5 / 5 |
| R08 | Dedicated security function / CISO | 5 / 5 |
| R09 | Incident history (last 24 months) | 5 / 5 |
| R10 | Breach notification SLA | 10 / 10 |
| R11 | Business continuity / DR | 5 / 5 |
| R12 | Subprocessors (fourth parties) | 0 / 0 |

## Answers as submitted

| Question | Answer |
|---|---|
| company_name | SecureVault Offsite Backup Pty Ltd |
| security_contact | Dana Whitfield, Head of Information Security |
| contact_email | security@securevault-example.com.au |
| date_completed | 2026-11-18 |
| iso_cert | Yes |
| iso_expiry | 2027-08-15 |
| soc2 | Yes |
| other_certs | None beyond ISO 27001 and SOC 2 |
| pentest | Yes |
| pentest_date | 2025-09-01 |
| data_types | Encrypted backup copies of client file servers and databases |
| data_location | United States (AWS us-east-1) |
| enc_rest | Yes |
| enc_transit | Yes |
| mfa | No, enforced for admin accounts only, not yet rolled out to all staff |
| access_reviews | Yes, quarterly |
| security_function | Yes |
| breach | No |
| breach_desc |  |
| breach_sla | 24 |
| bcp | Yes |
| bcp_tested | 2026-02-15 |

## Subprocessors

| Name | Purpose | Data | Location |
|---|---|---|---|
| ColdStore Infrastructure | Offsite cold-storage replication | Encrypted backups only | Singapore |

## Decision

### Decision recorded 2026-11-10

- **Decision:** approve-with-conditions
- **Reviewer:** Nikhil Kubsad
- **Recorded by (system user):** rcw-01wvep8tvoqdd88xk6cwxyzc
- **Conditions:** Enforce MFA for all staff with system access within 30 days; provide a written risk acceptance for offshore backup storage (AWS us-east-1) signed by the data owner (due 2026-12-10)
- **Risk acceptance:** MFA gap and offshore backup storage accepted on an interim basis given encryption at rest/in transit and quarterly access reviews; conditions below are mandatory to close the gap. Risk owner: IT Manager.
