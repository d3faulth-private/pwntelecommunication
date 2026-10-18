#!/usr/bin/env bash
# Passive, bounded loopback capture. Execute inside the approved isolated namespace.
set -euo pipefail
umask 077
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
usage() { echo "Usage: $0 {baseline|hardened} [seconds: 1..300]" >&2; exit 2; }
(( $# >= 1 && $# <= 2 )) || usage
case "$1" in baseline|hardened) ;; *) usage ;; esac
seconds=${2:-60}
[[ "$seconds" =~ ^[1-9][0-9]{0,2}$ ]] || usage
(( seconds <= 300 )) || usage
command -v dumpcap >/dev/null
command -v sha256sum >/dev/null
capture_dir="$root/captures"
[[ ! -L "$capture_dir" ]] || { echo 'Refusing captures symlink' >&2; exit 1; }
mkdir -p -- "$capture_dir"
chmod 700 -- "$capture_dir"
out=$(mktemp "$capture_dir/$1.XXXXXXXX.pcapng")
# Loopback-only pair constraints. GSUP source may be selected as 127.0.0.1.
filter='(sctp and port 2905 and host 127.0.0.2 and (host 127.0.0.3 or host 127.0.0.4)) or (tcp port 4222 and host 127.0.0.5 and (host 127.0.0.1 or host 127.0.0.3))'
printf 'Capture path: %s\n' "$out"
rc=0
dumpcap -i lo -p -n -f "$filter" -a "duration:$seconds" -a filesize:10240 -w "$out" || rc=$?
chmod 600 -- "$out"
sha256sum -- "$out" > "$out.sha256"
if (( rc )); then
  echo 'Capture failed/interrupted; retained partial evidence. Do not mark complete.' >&2
  exit "$rc"
fi
printf '%s\n' 'Capture stopped at time or size bound. Review drop counts and completeness.'
