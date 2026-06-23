#!/usr/bin/env bash
set -euo pipefail

echo "Continuum Lab full demo"
echo "======================="

./run_scanners.sh

echo
echo "Running Continuum Lab reasoning and evidence pipeline"
./run_lab.sh

echo
echo "Demo complete."
echo
echo "Start here:"
echo "- README.md"
echo "- evidence/demo-summary.md"
echo "- evidence/prioritized-risk-register.md"
echo "- evidence/remediation-plan.md"
echo "- evidence/evidence-bundle.md"
