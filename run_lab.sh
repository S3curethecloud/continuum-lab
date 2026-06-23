#!/usr/bin/env bash
set -euo pipefail

python3 engine/validate_finding.py
python3 engine/prioritize.py
python3 engine/generate_evidence.py

echo
echo "Continuum Lab evidence generated:"
echo "- evidence/validation-results.json"
echo "- evidence/prioritized-findings.json"
echo "- evidence/prioritized-risk-register.md"
echo "- evidence/decision-trace.md"
echo "- evidence/evidence-bundle.json"
echo "- evidence/evidence-bundle.md"
