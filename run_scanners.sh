#!/usr/bin/env bash
set -euo pipefail

echo "Continuum Lab scanner orchestration"
echo "==================================="

echo
echo "[1/3] Running Semgrep SAST adapter"
./scanners/semgrep/run_semgrep.sh

echo
echo "[2/3] Running Gitleaks secret scanning adapter"
./scanners/gitleaks/run_gitleaks.sh

echo
echo "[3/3] Running dependency-audit adapter"
./scanners/dependency-audit/run_dependency_audit.sh

echo
echo "Scanner outputs generated:"
echo "- scanners/semgrep/semgrep-output.json"
echo "- scanners/gitleaks/gitleaks-output.json"
echo "- scanners/dependency-audit/dependency-audit-output.json"
