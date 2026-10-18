# SS7 validation report — <ENGAGEMENT_REFERENCE>

Status: NOT EXECUTED. Classification: <CLASSIFICATION>. Date/window: <WINDOW>.
Owner/reviewer: <OWNER> / <REVIEWER>. Authorization record: <PRIVATE_REFERENCE>.

## Executive assessment

Objective: <OBJECTIVE>. Verified results: <NONE_UNTIL_TESTED>.
Impact limited to: <APPROVED_LAB_SCOPE>. Residual risk: <RISK>.
Do not extrapolate isolated results to a carrier network or claim GSMA certification.

## Reproducibility

Commit/profile: <SHA> / <PROFILE>. Installed daemon/library versions: <VERSIONS>.
Manual hashes and compatibility review: <RECORD>. Topology/containment evidence:
<PRIVATE_REFERENCE>. Effective configs, parser logs, clock offsets, capture losses,
external firewall product/version/policy and approved operation matrix: <RECORDS>.
Subscriber aliases only: <TEST_SIM_1_IMSI>, <TEST_SIM_1_MSISDN>.

## Results

| Scenario | Baseline observation | Hardened observation | Positive control | Evidence hash / private location | Verdict |
| --- | --- | --- | --- | --- | --- |
| <D-ID> | <OBSERVED> | <OBSERVED> | <RESULT> | <SHA256_REFERENCE> | NOT TESTED |

Allowed verdicts: PASS, FAIL, BLOCKED, INCONCLUSIVE, NOT TESTED. Distinguish
expected behavior, detector alert, enforcement decision and downstream observation.
MAP enforcement is BLOCKED until an external component is integrated and validated.

## Standards crosswalk

| Finding / local control | Document | Sponsor-approved edition | Exact clause/control ID | Evidence / applicability | Review status |
| --- | --- | --- | --- | --- | --- |
| <F-ID> / peer admission | GSMA FS.07 | <EDITION> | <VERIFY_IN_AUTHORIZED_COPY> | <EVIDENCE> | UNVERIFIED |
| <F-ID> / monitoring and operation policy | GSMA FS.11 | <EDITION> | <VERIFY_IN_AUTHORIZED_COPY> | <EVIDENCE> | UNVERIFIED |
| <F-ID> / risk treatment | GSMA FS.21 | <EDITION> | <VERIFY_IN_AUTHORIZED_COPY> | <EVIDENCE> | UNVERIFIED |
| <F-ID> / protocol semantics | Q.700; GSM 09.02; TS 29.002 | <EDITION> | <CLAUSE> | <EVIDENCE> | UNVERIFIED |

ETSI TS 101 220 applicability: <SIM_APPLICATION_NUMBERING_ONLY_OR_NOT_APPLICABLE>.
See methodology references; local rule IDs are not GSMA IDs.

## Findings, remediation and closure

Use `findings/F-01-template.md`. Record severity rationale, affected component,
owner, due date, before/after diff, regression results, unresolved TODOs and residual
risk acceptance. Evidence retention/deletion: <POLICY_AND_CONFIRMATION>.
Sign-off: <OPERATOR>, <SPONSOR_REVIEWER>, <DATE>.
