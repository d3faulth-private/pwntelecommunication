# Kali walkthrough

The offline path below is working and tested without telecom hardware. It requires
Python 3 and Git only, needs no sudo and does not start services or contact lab peers.
The live Osmocom path remains an integration task; do not start the fragments as a
complete mobile network.

## 1. Obtain main

For a new checkout:

```bash
git clone https://github.com/d3faulth-private/pwntelecommunication.git
cd pwntelecommunication
```

For an existing checkout instead:

```bash
cd ~/pwntelecommunication
git status --short
git switch main
git pull --ff-only origin main
```

If local edits or a divergent branch prevent updating, preserve those changes and
resolve the conflict; do not force-reset the checkout.

## 2. Run checks

```bash
bash scripts/check.sh
```

Expected: 20 tests pass, then the offline-check success message. No pip packages are
needed. These checks do not validate the Osmocom configuration parser or live behavior.

## 3. Run both synthetic examples

```bash
umask 077
mkdir -p runtime
chmod 700 runtime
run_dir=$(mktemp -d runtime/offline.XXXXXXXX)
python3 detection/analyze.py --events detection/fixtures/good.jsonl --policy detection/fixtures/policy.json --output "$run_dir/good-report.json"
python3 detection/analyze.py --events detection/fixtures/anomalies.jsonl --policy detection/fixtures/policy.json --output "$run_dir/anomaly-report.json"
echo "Detector exit code: $? (1 is expected for the anomaly fixture)"
python3 -m json.tool "$run_dir/anomaly-report.json"
```

Expected: good input gives `NO_ALERTS` and exit 0. Anomaly input gives `ALERTS`, exit 1,
and six alerts: SIG-01 ×1, SIG-02 ×1, MAP-01 ×3, MAP-03 ×1. The fixture exercises all
four implemented checks. MAP-02 remains unsupported. Reports stay under ignored
`runtime/`. A new directory on every run prevents overwriting earlier evidence.

## 4. Review actual configuration differences

```bash
bash scripts/diff-configs.sh
```

Expect ASP admission, routing-key allocation and 2G authentication changes. No MAP
screening command is added. BSC and HLR remain identical.

## 5. Collect the host prerequisite inventory

```bash
bash scripts/doctor.sh
```

Exit 1 means at least one binary is missing, not that the computer is damaged. Share
this output to choose the installation/version-validation path. It reports available
disk space, binary locations and installed Debian package versions; review local paths
before sharing. It does not install anything. If software is missing, inspect package
candidates before deciding on a compatible set:

```bash
apt-cache policy osmo-stp osmo-msc osmo-bsc osmo-hlr tshark wireshark-common
```

Do not assume the pinned documentation versions are available in Kali repositories.
Do not install/start system services just to make the inventory turn green.

## 6. Live lab integration gates (partially verified)

Existing evidence verifies startup, configured-peer signalling connectivity and the
peer-admission comparison; see [F-01](../findings/F-01-peer-admission.md). These are
retained observations, not proof of historical namespace containment or subscriber
service. Subscriber authentication and routing-key restrictions remain untested;
MAP screening remains unimplemented. The gates below still apply to future runs.

After the inventory is reviewed:

1. Snapshot a dedicated VM; confirm scope and containment. Keep package installation
   separate from execution. Use a disconnected VM or namespace for daemon tests.
2. Select compatible daemon/library builds and validate their effective configuration
   syntax using matching manuals. Resolve the PLMN, BTS, MGW and private HLR database
   TODOs only if those components are in scope. No RF configuration is supplied here.
3. Stage review copies using `bash scripts/provision.sh baseline --stage` and then
   `bash scripts/provision.sh hardened --stage`. A missing-prerequisite exit may occur
   after staging; it does not imply readiness. Paths are printed; files are private.
4. Validate parser/startup logs and listening sockets inside isolation. Prove normal
   approved BSC/MSC connectivity before comparing admission controls. Restore clean
   state between profiles to remove dynamic routes.
5. Only after the isolation and socket checks, run `bash scripts/capture.sh baseline 60`
   in the same namespace as the lab. Repeat for hardened. Review drop counts; unknown
   peers are outside this script's filter and require STP admission logs as evidence.
6. For MAP, select and document a separate test endpoint and enforcement component.
   Until then, MAP enforcement scenarios remain BLOCKED. No live MAP payload generator
   or firewall configuration is included.

No capture, subscriber database, SIM secret or real identifier should be committed or
uploaded for troubleshooting. Share sanitized diagnostics and private evidence references.
