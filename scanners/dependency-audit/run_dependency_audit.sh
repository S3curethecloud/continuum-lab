#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

echo "Running dependency-audit local scanner adapter..."
python3 scanners/dependency-audit/run_dependency_audit.py
