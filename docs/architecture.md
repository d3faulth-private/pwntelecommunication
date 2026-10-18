# Architecture and capability boundary

## Isolated topology

Use one dedicated Linux network namespace or disconnected VM with only loopback
for this signalling skeleton. No uplink, NAT, forwarding, carrier routes or public
signalling peers. Loopback binding alone does not isolate other processes on the host.
BTS and RF integration is deliberately absent; any later integration needs its own
approved containment and configuration review. MGW is also outside this file set.

| Component | Local address | Signalling role | Point code / routing context |
| --- | --- | --- | --- |
| OsmoSTP | 127.0.0.2:2905 SCTP | SG, listener | 0.0.0 / — |
| OsmoBSC | 127.0.0.4:2905 SCTP | ASP, client of STP | 1.1.1 / 1 |
| OsmoMSC | 127.0.0.3:2905 SCTP | ASP, client of STP | 3.3.3 / 3 |
| OsmoHLR | 127.0.0.5:4222 TCP | GSUP server | No SS7 point code |

BSC ↔ STP ↔ MSC carries the A-interface (BSSAP/SCCP/M3UA/SCTP).
**OsmoMSC speaks GSUP to OsmoHLR, not MAP.** No native MAP subscriber traffic can
be inferred from this A-interface topology. **OsmoSTP currently routes by point code
only** in the documented topology; do not infer GT translation, MAP opcode screening,
or caller-to-subscriber authorization from point-code routes.

## What the diff enforces

Both STP profiles retain the same explicit peers, routing contexts and full-mask
routes (`7.255.7`, ITU 14-bit point code). Baseline additionally permits dynamic ASP
creation and dynamic routing-key allocation. Hardened restricts admission to configured
source IP/port peers and disallows dynamic allocation. This is transport admission and
route registration control, not cryptographic authentication or per-message OPC validation.
MS authentication becomes required at MSC; this is a 2G access control, not MAP filtering.
BSC and HLR files are deliberately byte-identical across profiles to preserve topology.

## Required external controls (not implemented)

MAP screening needs a sponsor-selected MAP-capable firewall/proxy and approved test
endpoint, separate from GSUP. Keep the chosen topology fixed between baseline and
hardened runs: baseline policy observes; hardened policy enforces a default-deny
(peer, direction, operation, application-context, destination) allowlist. Require
transaction/context consistency and audit decisions. No vendor syntax is invented here.
TODO: identify product/version, documented configuration, placement, authorized operation
matrix, and proof that traffic cannot bypass it before marking MAP tests executable.

A namespace firewall must restrict GSUP to the observed MSC source and management to
the operator path. Validate actual bind/source behavior and all listening sockets;
`hlr remote-ip` selects the destination, not the MSC's GSUP source address. No unsupported
native GSUP ACL is claimed. Control this trust boundary equally in both profiles.

## Configuration status and source traceability

These are signalling fragments. TODOs for PLMN, BTS, MGW, database provisioning and
external policy must be resolved in private runtime copies before a complete network
can be started. No start script is supplied. Do not substitute subscriber tokens into
tracked files. Manual examples contain inconsistent ASP names in places; the names
here are internally consistent. Use `transport-role` from the versioned VTY references
rather than the older `sctp-role` spelling seen in user-manual examples.

| Directives / behavior | Official manual location |
| --- | --- |
| `cs7 instance`, ASP/AS, `routing-key`, `route-table`, `listen` | MSC user manual, “Static Routing Key Configuration”; STP user manual, SS7 configuration sections |
| `accept-asp-connections`, `xua rkm routing-key-allocation` | STP user manual §5.2.1; VTY config-cs7 / config-cs7-listen |
| `role`, `transport-role`, `no shutdown` | Each corresponding VTY reference, config-cs7-asp |
| `authentication`, `cs7-instance-a`, HLR `remote-ip` / `remote-port` | MSC VTY config-net / config-msc / config-hlr |
| `sccp-address`, `routing-indicator`, `msc-addr` | BSC VTY config-cs7 / config-sccpaddr / config-msc |
| `hlr` → `gsup` → `bind ip`, `ctrl bind`, `line vty bind` | HLR user manual §5.4 and VTY reference |
| `line vty bind` in other daemons | Corresponding VTY config-line node |

Documentation snapshots consulted (SHA-256 identifies the retrieved PDF, not binaries):

- [OsmoSTP 2.2.0 usermanual](https://downloads.osmocom.org/docs/osmo-stp/2.2.0/osmostp-usermanual.pdf); SHA-256 `8d5805f7d2efb4c29b4b20554096881d0d5af71ebd713694f9c6f9b9043f1db8`.
- [OsmoSTP 2.2.0 vty-reference](https://downloads.osmocom.org/docs/osmo-stp/2.2.0/osmostp-vty-reference.pdf); SHA-256 `4048c3261838df14ed6c1b297795f1d41182b7bf598cc508093bef0d16fd9868`.
- [OsmoMSC 1.14.0 usermanual](https://downloads.osmocom.org/docs/osmo-msc/1.14.0/osmomsc-usermanual.pdf); SHA-256 `7b0819796f49c227bcd28d82827f5c20a3f78190953b8b44a2386d7ba0c6dc2d`.
- [OsmoMSC 1.14.0 vty-reference](https://downloads.osmocom.org/docs/osmo-msc/1.14.0/osmomsc-vty-reference.pdf); SHA-256 `4b3913f3031d9c48b08dfae45705a822fa312acc0c089b99dbf03af86d1ca85e`.
- [OsmoBSC 1.14.1 usermanual](https://downloads.osmocom.org/docs/osmo-bsc/1.14.1/osmobsc-usermanual.pdf); SHA-256 `e50eef5908a0ebdf585b50c68b5452efc4c33cd58dddf6dfb4c8f6699479f309`.
- [OsmoBSC 1.14.1 vty-reference](https://downloads.osmocom.org/docs/osmo-bsc/1.14.1/osmobsc-vty-reference.pdf); SHA-256 `bbe893e7bee3553b96c576fe54dc016db274db5f1e1bc3e117c341ef3cfa6a5f`.
- [OsmoHLR 1.9.2 usermanual](https://downloads.osmocom.org/docs/osmo-hlr/1.9.2/osmohlr-usermanual.pdf); SHA-256 `dd1aeccc23e1b888bde660d9a498d06990faa5c5233078c962ee7c3e76c8aafd`.
- [OsmoHLR 1.9.2 vty-reference](https://downloads.osmocom.org/docs/osmo-hlr/1.9.2/osmohlr-vty-reference.pdf); SHA-256 `ebb3b8632e16ad5d64c7a1844f250221a4b622031bfefdbb9c8b4e1aa231c339`.

Use these versioned documents for reproducibility. Record actual installed daemon and
libosmo-sigtran versions, package origins and parser output in the private report;
version compatibility is not established merely by citing a manual.

## Kali runtime compatibility finding

OsmoSTP 2.1.0-3+b1 rejected ASP `no shutdown` during the first isolated startup
check. Both STP profiles now omit this directive. The
[2.1.0 VTY reference](https://downloads.osmocom.org/docs/osmo-stp/2.1.0/osmostp-vty-reference.pdf)
does not list it in config-cs7-asp. This fixes the observed parser error only;
startup, effective ASP state and connectivity still require a repeat test.
MSC/BSC compatibility has not yet been runtime-validated. Offline tests do not
invoke Osmocom parsers and could not detect this version mismatch.
