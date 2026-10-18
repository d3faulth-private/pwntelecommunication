#!/usr/bin/env bash
# Show the complete baseline-to-hardened comparison; no network activity.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
rc=0
diff -ru -- "$root/configs/baseline" "$root/configs/hardened" || rc=$?
# diff: 0 identical, 1 expected differences, >1 operational failure.
if (( rc > 1 )); then exit "$rc"; fi
