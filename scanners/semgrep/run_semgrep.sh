#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

OUTPUT="scanners/semgrep/semgrep-output.json"
RULES="scanners/semgrep/rules/continuum-lab-sast.yml"
TARGET="apps/vulnerable-node-api"

echo "Running Semgrep local SAST scan..."
echo "Target: $TARGET"
echo "Rules:  $RULES"
echo "Output: $OUTPUT"

if command -v semgrep >/dev/null 2>&1; then
  semgrep scan --config "$RULES" --json "$TARGET" > "$OUTPUT"
elif command -v docker >/dev/null 2>&1; then
  docker run --rm \
    -v "$ROOT_DIR:/src" \
    -w /src \
    semgrep/semgrep:latest \
    semgrep scan --config "$RULES" --json "$TARGET" > "$OUTPUT"
else
  echo "ERROR: semgrep or docker is required to run the Semgrep adapter." >&2
  exit 1
fi

echo "Semgrep scan complete."
echo "Wrote $OUTPUT"
