#!/usr/bin/env bash
# Conversation viewer. See tools/conversation.py for the why.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$DIR/conversation.py" "$@"
