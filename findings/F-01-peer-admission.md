# F-01 — Unconfigured peer admission differs between profiles

D-01: observed transport admission difference in the local lab. Severity is not
assigned: unauthorized signalling delivery was not demonstrated. This finding
records retained evidence, not a complete security acceptance test.

Repository reviewed: `57ad0ad75f8d2b29f405684b58a9475ada6c3b8f` (main).
This identifies the reviewed checkout; retained logs do not independently establish
which commit or effective configuration produced the historical run.

Installed package versions verified locally with `dpkg-query` on 2026-10-18:

| Package | Version |
| --- | --- |
| osmo-stp | 2.1.0-3+b1 |
| osmo-msc | 1.13.0+dfsg1-2 |
| osmo-bsc | 1.13.0-2 |
| osmo-hlr | 1.9.4+dfsg1-1 |
| libosmo-sigtran11 | 2.1.0-3+b1 |

These are current installed package versions, not independently proven historical
process versions. No service was launched during this documentation review.

## Verified evidence

References below are private, ignored paths relative to the repository root;
selected messages contain only lab addresses and protocol state.

- Four-component operation: `runtime/four-core.Lkr3avOF/hlr.log:1` says
  `hlr starting`; line 7 accepts the connection from loopback `127.0.0.1`.
  `msc.log:4,16` records GSUP connecting to `127.0.0.5:4222` and connection done.
  The signalling exchanges below establish overlapping STP/MSC/BSC operation,
  alongside the HLR connection. Exact simultaneous launch timing is not recorded.
- Configured-peer activation: `msc.log:20` and `bsc.log:17` report
  `Received NOTIFY Type State Change:AS Active` for their respective configured ASPs.
  In `captures/hardened.PXrhHsTM.pcapng`, frames 23/27/31/32 show MSC
  ASPUP/ASPUP_ACK/ASPAC/ASPAC_ACK; frames 46/48/51/53 show the BSC equivalents.
- BSSMAP connectivity: capture frames 57–60 show Reset from BSC through STP to MSC
  and Reset Acknowledge back. `bsc.log:18–20` reports `RESET ACK from MSC`,
  `link up`, and `BSSMAP association is up`.
- Capture accounting: `capture.log:5–6` reports `Packets captured: 76` and
  `76/0` received/dropped, with all reported drop counters zero. Offline decoding
  independently counted 76 frames. Zero reported drops is not proof of complete
  coverage of all lab traffic.
- Baseline admission: `runtime/peer-admission.do9005TU/baseline/stp.log:4–8`
  identifies `asp-dyn-0`, associates it with unconfigured loopback peer
  `127.0.0.6:2905`, and reports `RKM: Found existing AS for RCTX 1`.
  `baseline/sockets.log:3–6` records an established SCTP association for that peer.
- Hardened enforcement: `runtime/peer-admission.do9005TU/hardened/stp.log:4–5`
  explicitly reports that peer's `connection without matching ASP definition and
  no dynamic registration enabled, terminating`. This is enforcement evidence
  at STP, rather than an alert alone.
- Delivery limitation: `baseline/bsc.log:14–16` reports
  `{AS_INACTIVE}: Event AS-TRANSFER.req not permitted`. Dynamic ASP creation and
  an established association do not demonstrate unauthorized signalling delivery.

## Integrity and preservation

The existing `runtime/peer-admission.do9005TU/SHA256SUMS` was preserved and all
seven listed files passed verification. New private manifest
`runtime/four-core.Lkr3avOF/SHA256SUMS.review-20261018` covers the five existing
service/capture logs and `captures/hardened.PXrhHsTM.pcapng`; all six entries
passed verification from the repository root. Hashes preserve a review-time
integrity reference, not proof of origin or historical configuration.
Captures, raw logs, databases and manifests remain ignored and untracked.

## Limits and next step

Historical namespace containment is not independently proven by the retained
service logs. Loopback addresses and the capture's loopback interface do not
establish namespace membership or absence of external routes. MSC logged wildcard
SMPP and SGs listeners (`msc.log:2,13`); this reinforces the need for independently
recorded namespace containment. The observed MSC-to-HLR source was `127.0.0.1`.

The configured-peer positive control comes from the separate four-core run;
retained admission-run evidence does not demonstrate configured peers operating
alongside the rejected peer in that same run. Transient reconnect/shutdown and
initial AS_INACTIVE messages are present; successful later activation does not
establish uninterrupted availability.

MAP screening remains unimplemented. Subscriber authentication and routing-key
restrictions remain untested. Finding an existing AS for RCTX 1 does not test
allocation of a new routing key or installation of an unauthorized route.
No subscriber service, RF behavior, cryptographic peer authentication or carrier
network security conclusion follows from these results. Standards mappings remain
unverified; no GSMA compliance claim is made.

For a separately authorized future run, preserve namespace/process/socket and
route inventory, effective configuration hashes and process versions; restore
clean state between profiles and repeat admission with concurrent configured-peer
positive controls inside the existing ss7lab namespace. No new network test or
service launch is part of this documentation step.
