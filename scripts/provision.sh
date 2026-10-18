#!/usr/bin/env bash
# Stage private review copies only. Does not install, launch or modify networking.
set -euo pipefail
umask 077
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
usage() { echo "Usage: $0 {baseline|hardened} [--stage]" >&2; exit 2; }
(( $# >= 1 && $# <= 2 )) || usage
profile=$1
case "$profile" in baseline|hardened) ;; *) usage ;; esac
[[ ${2:-} == '' || ${2:-} == --stage ]] || usage
missing=0
for tool in osmo-stp osmo-msc osmo-bsc osmo-hlr dumpcap tshark sha256sum; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf 'Found: %s\n' "$tool"
  else
    printf 'Missing lab prerequisite: %s\n' "$tool" >&2
    missing=1
  fi
done
printf '%s\n' 'Review docs/authorization.md and docs/architecture.md.'
printf '%s\n' 'No daemons will be installed or started; MAP enforcement remains an external TODO.'
if [[ ${2:-} != --stage ]]; then
  printf '%s\n' 'Preview only. Use --stage to create a private review directory.'
  exit "$missing"
fi
# Atomic new directory; never overwrite prior runtime evidence or follow its symlink.
runtime="$root/runtime"
[[ ! -L "$runtime" ]] || { echo 'Refusing runtime symlink' >&2; exit 1; }
mkdir -p -- "$runtime"
chmod 700 -- "$runtime"
dest=$(mktemp -d "$runtime/$profile.XXXXXXXX")
for name in osmostp osmomsc osmobsc osmohlr; do
  install -m 600 -- "$root/configs/$profile/$name.cfg" "$dest/$name.cfg"
done
printf 'Staged review copies: %s\n' "$dest"
if (( missing )); then
  echo 'Staging succeeded; prerequisites incomplete. Not ready to run.' >&2
  exit 1
fi
