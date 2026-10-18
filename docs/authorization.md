# Authorization record (template; not evidence of approval)

- Sponsor / engagement reference: <SPONSOR_REFERENCE>
- Signed scope record, private location and hash: <SCOPE_RECORD>
- Approver and operator: <APPROVER>, <OPERATOR>
- Approved time window and timezone: <WINDOW>
- Equipment inventory / isolated namespace: <EQUIPMENT>, <NAMESPACE>
- Approved simulated peers, point codes and ports: <PEER_INVENTORY>
- Test SIM inventory aliases: <TEST_SIM_1_IMSI>, <TEST_SIM_1_MSISDN>
- SIM key reference only: <TEST_SIM_1_KI_REFERENCE>
- Capture custodian, retention deadline and deletion confirmation: <EVIDENCE_POLICY>
- Stop contact / incident escalation channel: <CONTACT>

The user describes written authorization; the signed record must be verified by the
engagement owner before execution. This repository is not an authorization grant.
No real subscriber identifiers, Ki values, approval signatures or personal contacts
belong in tracked copies of this template.

Pre-run evidence: no carrier interconnect, no uplink/default route, no forwarding,
only owned endpoints, test-only subscriber database, management isolation, and RF
containment if radios are separately approved. Record topology and socket inventory.
Stop if scope, routing, RF containment or ownership is uncertain, unexpected subscribers
appear, or traffic leaves the boundary. Disconnect the lab and notify the approved
contact; preserve evidence privately. Never expand scope to investigate an unknown peer.

Restore a clean snapshot between profiles; verify dynamic ASPs/routes from baseline
are gone. Retain raw captures with restrictive permissions and approved encryption;
share only reviewed, sanitized findings. Deletion includes backups and private DB copies.
