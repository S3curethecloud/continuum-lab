#!/usr/bin/env bash
set -euo pipefail

./scanners/dependency-audit/run_dependency_audit.sh

python3 engine/ingest_findings.py
python3 engine/validate_finding.py
python3 engine/prioritize.py
python3 engine/recommend_fix.py
python3 engine/generate_evidence.py
python3 engine/generate_demo_summary.py

echo
echo "Continuum Lab evidence generated:"
echo "- scanners/dependency-audit/dependency-audit-output.json"
echo "- evidence/findings.json"
echo "- evidence/validation-results.json"
echo "- evidence/prioritized-findings.json"
echo "- evidence/prioritized-risk-register.md"
echo "- evidence/decision-trace.md"
echo "- evidence/remediation-plan.json"
echo "- evidence/remediation-plan.md"
echo "- evidence/evidence-bundle.json"
echo "- evidence/evidence-bundle.md"
echo "- evidence/demo-summary.md"
