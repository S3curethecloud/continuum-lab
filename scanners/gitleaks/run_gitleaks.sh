#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

OUTPUT="scanners/gitleaks/gitleaks-output.json"
CONFIG="scanners/gitleaks/gitleaks.toml"
TARGET="apps/vulnerable-node-api/test/fixtures"

echo "Running Gitleaks-style local secret scan..."
echo "Target: $TARGET"
echo "Config: $CONFIG"
echo "Output: $OUTPUT"

rm -f "$OUTPUT"

set +e

if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect \
    --source "$TARGET" \
    --config "$CONFIG" \
    --report-format json \
    --report-path "$OUTPUT" \
    --no-git
  status=$?
elif command -v docker >/dev/null 2>&1; then
  docker run --rm \
    -v "$ROOT_DIR:/repo" \
    -w /repo \
    zricethezav/gitleaks:latest \
    detect \
    --source "$TARGET" \
    --config "$CONFIG" \
    --report-format json \
    --report-path "$OUTPUT" \
    --no-git
  status=$?
else
  echo "ERROR: gitleaks or docker is required to run the Gitleaks adapter." >&2
  exit 1
fi

set -e

# Gitleaks returns a non-zero code when leaks are found.
# In this lab, findings are expected and are not treated as runner failure.
if [ "$status" -ne 0 ] && [ "$status" -ne 1 ]; then
  echo "ERROR: Gitleaks runner failed with status $status" >&2
  exit "$status"
fi

if [ ! -f "$OUTPUT" ]; then
  echo "[]" > "$OUTPUT"
fi

echo "Gitleaks-style scan complete."
echo "Wrote $OUTPUT"
