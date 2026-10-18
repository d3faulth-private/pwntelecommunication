# Methodology

## Gates and reproducibility

1. Complete the private authorization record and containment evidence.
2. Record commit SHA, package versions/origins, manual hashes, clock synchronization,
   topology, approved peer/operation matrix, capture vantage and scenario ID.
3. Stage configs; resolve TODOs privately. Use each installed daemon's documented
   configuration validation facility if available; otherwise validate startup only
   inside the disconnected namespace. Do not invent a universal `--check-config` flag.
4. Save parser output and effective configuration. Verify all listeners, ASP state,
   routing contexts and routes. Confirm the known-good endpoint pair still works.
5. Capture baseline observations; restore a clean snapshot and restart with hardened
   copies. Repeat identical approved stimuli and positive controls. Check rejection at
   the enforcing component and absence downstream; an alert alone is not blocking proof.
6. Hash evidence, record gaps and complete the report. No runtime test has been performed
   by this scaffold. Never label missing traffic as proof of successful screening.

## Demonstrations (no payload generation)

| ID | Flaw class / approved evidence input | Baseline expectation | Detection | Hardened acceptance |
| --- | --- | --- | --- | --- |
| D-01 | Unconfigured sponsor-owned ASP, ordinary connection only | Admission may succeed | SIG-01 | Rejected; approved BSC/MSC still connect |
| D-02 | Sponsor-provided registration test record for an unassigned lab point code | Dynamic allocation may be accepted | SIG-02 | No new route/AS; explicit approved routes retained |
| D-03 | Paired approved 2G authentication test on test SIM | Optional authentication permits unauthenticated attach when otherwise eligible | MSC authentication logs | Authentication required; known-good test SIM succeeds; needs separately completed radio/PLMN setup |
| D-04 | Sanitized offline MAP record outside approved peer/operation/context tuple | Observe-only external policy logs it | MAP-01 | External enforce mode denies it, with correlated decision evidence; BLOCKED until external component exists |
| D-05 | Sanitized MAP transaction-context inconsistency or rate-window fixture | Alert-only | MAP-02 / MAP-03 | External policy disposition matches approved requirements; valid dialogue preserved; BLOCKED for runtime enforcement |

Use provided benign fixtures or the sponsor's existing validation suite only. This
repository provides neither traffic generation nor replay commands. Offline detector
validation cannot establish on-wire mitigation. Unexpected MAP on the native A/GSUP
leg is a topology/decode investigation, not evidence that GSUP is MAP.

## Offline implementation

See [the offline detector contract](offline-detector.md) and
[Kali walkthrough](kali-next-steps.md). The standard-library detector evaluates
normalized records for four rules and generates an input/configuration hash manifest.
Its synthetic tests do not validate the radio/core network or enforcement. MAP-02,
a PCAP normalizer and external MAP enforcement remain pending.

## Capture and analysis

`bash scripts/capture.sh baseline 60` captures only loopback traffic for the specified
lab endpoint pairs, with a duration and size cap. Run it inside the approved namespace;
no `any` interface or external-interface option is supplied. It writes a private
`captures/*.pcapng` plus a hash. Dumpcap capabilities must already be set by the operator;
the script does not grant privileges. Check reported dropped packets and capture completeness.

Capture filters are BPF, not Wireshark display filters. The script uses `sctp` for
M3UA and `tcp port 4222` for GSUP, bounded by endpoint pairs. Useful display filters:

```text
sctp
m3ua
sccp
bssap
tcap
gsm_map
tcp.port == 4222
```

For separately approved MAP evidence, inspect offline with
`tshark -n -r <PRIVATE_CAPTURE_PATH> -Y 'tcap || gsm_map'`.
Verify protocol/field support against `tshark -G protocols` and `tshark -G fields`
for the installed build; nonstandard ports may require a reviewed Decode As setting.
TCP port 4222 filtering selects transport traffic, not proof of valid GSUP decoding.
Do not export full packet trees into the public repository. Normalize decoded events
as specified in the YAML; unknown/missing fields produce a data-quality alert, never
an implicit pass. Deduplicate SCTP retransmissions and normalize direction before rate
or dialogue checks. Maintain an independent expected-event count to expose capture loss.

## Standards and mapping discipline

- [ITU-T Q.700](https://www.itu.int/rec/T-REC-Q.700): SS7 architecture and terminology.
- [GSM 09.02, ETSI work item](https://portal.etsi.org/webapp/WorkProgram/Report_WorkItem.asp?WKI_ID=6076): historical MAP specification.
- [3GPP TS 29.002 archive](https://www.3gpp.org/ftp/Specs/archive/29_series/29.002/): MAP procedures/encoding; select the release matching the approved endpoint.
- [ETSI TS 101 220](https://www.etsi.org/deliver/etsi_ts/101200_101299/101220/18.02.00_60/ts_101220v180200p.pdf): smart-card application-provider numbering, **not** GSM 09.02 or MAP. Relevant only if SIM application identifiers enter scope.
- [GSMA interworking security catalogue](https://www.gsma.com/solutions-and-impact/technologies/security/cybersecurity-knowledge-base/interworking-security/): FS.07 (SS7/SIGTRAN security), FS.11 (monitoring/firewall guidance), FS.21 (risk-based interconnect security recommendations).
- [Wireshark tshark manual](https://www.wireshark.org/docs/man-pages/tshark.html) and [dumpcap manual](https://www.wireshark.org/docs/man-pages/dumpcap.html): capture versus display filters and bounded capture.

GSMA document titles establish relevance, not compliance. Sponsor-provided authorized
copies must supply exact edition, clause/control ID and applicability; these were not
provided. Keep mappings `UNVERIFIED` until reviewed. Do not invent FS.11 control IDs
or describe FS.11 as a penetration-testing procedure. The report records local controls
separately from GSMA references. No claim of reproducing a specific GSMA flaw is made
without matched procedure, source clause and observed evidence.
