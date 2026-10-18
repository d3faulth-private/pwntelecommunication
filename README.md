# pwntelecommunication

Authorized, isolated SS7/SIGTRAN validation lab: configuration comparison,
passive detection design, evidence handling and reporting. No carrier interconnect;
only sponsor-owned equipment and test SIMs. No payloads or live-network procedures.

**Status: reviewable lab scaffold, not a turnkey network or a complete SS7 firewall.**
The four native daemons carry BSSAP over SCCP/M3UA and GSUP, not a MAP test service.
MAP scenarios require a separately approved MAP endpoint/firewall or sanitized offline
records. Their screening and operation restrictions remain explicit integration TODOs.

Local evidence now verifies four-component startup, configured-peer M3UA activation
and BSSMAP Reset/Acknowledge, plus baseline dynamic ASP creation and hardened
unconfigured-peer rejection. See [the sanitized D-01 finding](findings/F-01-peer-admission.md)
for evidence and limits. Unauthorized signalling delivery was not demonstrated;
subscriber authentication and routing-key restrictions remain untested. Historical
namespace containment is not independently proven by the retained service logs.

## Start on Kali

Follow [the step-by-step walkthrough](docs/kali-next-steps.md). First run
`bash scripts/check.sh`, then the two synthetic offline examples.
The detector requires only Python 3; no telecom packages are needed for those steps.

## Review

1. Read [authorization](docs/authorization.md) and [architecture](docs/architecture.md).
2. Inspect `bash scripts/diff-configs.sh` (exit 0 also when expected differences exist).
3. Run `bash scripts/provision.sh baseline` to check prerequisites and preview staging.
4. Stage private review copies with `bash scripts/provision.sh hardened --stage`.
5. Complete the topology TODOs and the [methodology](docs/methodology.md) acceptance gates
   on the sponsor's isolated host. These scripts do not install or start daemons.

| Control | Baseline | Hardened |
| --- | --- | --- |
| New ASP admission | Dynamic permitted | Preconfigured IP/port peers only |
| Routing-key allocation | Dynamic permitted | Static only |
| 2G MS authentication | Optional | Required |
| MAP screening / operation restriction | Not implemented | External component TODO; not enabled by these files |
| BSC / HLR topology | Fixed | Identical |

Config syntax is grounded in the linked official manuals and VTY references; the
versions are documentation baselines, not claims about installed software or a tested
compatibility matrix. Runtime parsing, interoperation and enforcement need lab verification.

[Detection specifications](detection/rules/map-anomalies.yaml) describe the broader
design. The [offline detector](docs/offline-detector.md) now implements SIG-01,
SIG-02, MAP-01 and MAP-03 against normalized JSON records; MAP-02 and direct PCAP
decoding remain unimplemented. It produces an integrity manifest and never blocks
traffic. Synthetic fixtures and 20 automated tests are included. Use the
[report](docs/report-template.md) and [finding](findings/F-01-template.md) templates
without treating expected outcomes as observed results.

Never commit captures, subscriber identifiers, SIM keys or the subscriber database.
Keep real values in private `secrets/` storage; tracked examples use tokens such as
`<TEST_SIM_1_IMSI>`. `.gitignore` is not a substitute for inspecting staged changes.
