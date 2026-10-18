#!/usr/bin/env bash
# Local/CI checks only; no daemons or captures are started.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd -- "$root"
for file in scripts/*.sh; do bash -n "$file"; done
python3 -m unittest discover -s tests -v
git diff --check
printf '%s\n' 'PASS: offline tests and shell syntax. Live lab is not validated.'
