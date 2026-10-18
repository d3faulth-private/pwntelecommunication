# Offline detector and evidence manifest

`detection/analyze.py` uses only the Python standard library. It reads JSON Lines
(one normalized event object per line) and a JSON policy. It makes no network calls,
does not open PCAPs, and cannot block traffic. The YAML remains the broader design
specification; this implementation supports the explicitly listed subset below.

| Rule | Implemented check | Limitation |
| --- | --- | --- |
| SIG-01 | Peer alias, source IP and source port match one approved tuple | Alias must come from trusted inventory; does not authenticate a peer |
| SIG-02 | Peer alias, point code and routing context match one approved tuple | An input registration record alone does not prove installation of a route |
| MAP-01 | Exact peer/direction/operation/context/destination tuple allowlist | No ASN.1 decoding or inferred authorization |
| MAP-03 | More than the configured count in `(t-60s, t]` | Grouped by sensor, peer and operation; requires calibrated threshold |
| MAP-02 | **Not implemented** | Needs validated TCAP decoder and bidirectional dialogue correlation |

The synthetic fixtures use `lab-operation` and `lab-context`, which are arbitrary
labels, not MAP protocol values. A threshold of 2 is for exercising the test only.
Never use the fixture policy as a production policy or a real engagement allowlist.

## Input contract

All records require these fields, with no extra fields:

| Field | Meaning |
| --- | --- |
| `timestamp_utc` | ISO timestamp ending in `Z`; records sorted chronologically |
| `sensor_id` | Stable, pseudonymous capture vantage identifier |
| `event_id` | Stable original-event alias, retained for duplicate records |
| `scenario_id` | Approved scenario alias |
| `protocol` | `M3UA` or `MAP`, according to kind |
| `peer_id` | Inventory-derived alias, not a claimed identity from a packet |
| `direction` | `inbound` or `outbound`, relative to the same documented boundary |
| `kind` | One of the three kinds below |

Additional fields by kind:

- `association` (`M3UA`): `source_ip`, integer `source_port` (1–65535).
- `registration` (`M3UA`): ITU `point_code` string and integer `routing_context`.
- `map_invoke` (`MAP`): `operation`, `application_context`, `destination_alias`.

Aliases start with a letter and contain only letters, digits, underscore, dot, colon
or hyphen (maximum 80 characters). These constraints do not anonymize data: the
operator must remove subscriber identifiers and secrets before normalization.
Policy fields follow `detection/fixtures/policy.json`; use a private copy for real
engagement data. An empty MAP tuple list or null rate threshold yields BLOCKED for
that check, never implicit acceptance. Policy syntax errors stop the run.

The normalizer is **not provided**. It must validate protocol decoding, confirm complete
capture coverage and retain evidence references privately. Identical `(sensor_id,event_id)`
records count once; changed contents under the same key are a data-quality error.
Packet-level retransmission detection is the normalizer's responsibility. Overlapping
sensors are counted independently and must not be summed as unique global traffic.
Unsupported event kinds, extra fields and malformed/out-of-order records yield
INCONCLUSIVE. Missing records cannot be discovered without an independent count.
Each input file is capped at 10 MiB. Do not split a rate-analysis window across separate
runs and assume counts are continuous: state is local to one invocation.

## Results and exit codes

The output includes alert rule IDs and source line numbers, quality errors, blocked
checks, per-rule evaluation counts, unsupported rules, and SHA-256 hashes of input,
policy, analyzer and all eight repository configs. Config hashes identify the repository
copies, **not** proof of the effective running configuration. It never copies raw input
records into the report. Private input retention is needed to resolve line references.

| Exit | Meaning |
| --- | --- |
| 0 | Valid nonempty input; no alerts or blocked checks among implemented evaluations |
| 1 | Alerts found, with no blocked checks or quality errors |
| 2 | Input/policy/output failure, including attempted overwrite |
| 3 | Incomplete evaluation: quality errors, blocked checks or empty input; alerts may coexist |

`NO_ALERTS` is not a security pass or complete rule coverage. Always review
`not_evaluated`, `unsupported_rules`, `blocked` and `data_quality`.
Output files are created exclusively with mode 0600, and existing outputs are never
overwritten. Create a private output directory first. Hashes provide integrity
references, not signatures, encryption or proof of origin.
