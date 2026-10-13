#!/usr/bin/env bash
# Claim audit. See tools/audit.py for the why.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$DIR/audit.py" "$@"
