#!/usr/bin/env bash
# Read-only inventory. Does not install packages, start services or capture traffic.
set -euo pipefail
printf '%s\n' 'SS7 lab prerequisite inventory (not a runtime certification)'
uname -srmo
df -h .
missing=0
for tool in python3 git osmo-stp osmo-msc osmo-bsc osmo-hlr dumpcap tshark; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf 'FOUND %s: %s\n' "$tool" "$(command -v "$tool")"
  else
    printf 'MISSING %s\n' "$tool"
    missing=1
  fi
done
if command -v dpkg-query >/dev/null 2>&1; then
  for package in osmo-stp osmo-msc osmo-bsc osmo-hlr tshark wireshark-common; do
    dpkg-query -W -f='${Package} ${Version} ${Status}\n' "$package" 2>/dev/null || true
  done
fi
printf '%s\n' 'No services started. MAP enforcement and daemon configuration validation remain pending.'
exit "$missing"
