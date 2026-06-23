# Continuum Lab Demo Checklist

This checklist is for running and presenting the Continuum Lab v0.1 demo.

Continuum Lab is a safe, local, provider-neutral security reasoning lab. It demonstrates how scanner findings can be normalized, validated, enriched with context, prioritized by business risk, mapped to remediation guidance, and packaged into evidence artifacts.

## Demo Goal

Show that scanner findings alone are not enough.

The demo proves that context and validation change risk decisions:

```text
Semgrep          -> FIND-001 -> P0
Dependency audit -> FIND-002 -> P2
Gitleaks         -> FIND-003 -> P4
Pre-Demo Setup

Required local tools:

Git
Python 3
Docker

Recommended clean test:

cd /tmp
rm -rf continuum-lab
git clone https://github.com/S3curethecloud/continuum-lab.git
cd continuum-lab

Optional syntax check:

python3 -m py_compile engine/*.py scanners/dependency-audit/run_dependency_audit.py
Run the Full Demo
./run_demo.sh

This runs:

Semgrep SAST adapter
Gitleaks secret scanning adapter
Dependency-audit adapter
Discovery ingestion
Lab-only validation
Context-aware prioritization
Remediation recommendation
Evidence bundle generation
Executive demo summary generation
Expected Scanner Output

Expected scanner adapter summary:

Semgrep adapter findings: 1
Gitleaks adapter findings: 1
Dependency adapter findings: 1

Expected normalized finding count:

Discovered 3 local lab findings.
Validated 3 findings using lab-only rules.
Prioritized 3 findings.
Expected Risk Register

Open:

cat evidence/prioritized-risk-register.md

Expected outcome:

Finding	Expected Priority	Why
FIND-001	P0	Customer-facing, prod-like, internet reachable, sensitive data, confirmed in lab
FIND-002	P2	Critical dependency, but dev/internal/non-reachable with compensating controls
FIND-003	P4	Secret-like scanner hit, but validation classifies it as likely test fixture
What to Show First

Start with:

README.md
evidence/demo-summary.md
evidence/prioritized-risk-register.md
evidence/decision-trace.md
evidence/remediation-plan.md
evidence/evidence-bundle.md
Suggested Demo Flow
1. Open with the thesis

Scanner findings are useful, but scanner severity alone is not enough for operational prioritization.

This lab shows how local scanner results become evidence-backed security decisions.

2. Show the scanner triad
Semgrep          -> SAST
Gitleaks         -> secrets
Dependency audit -> dependency risk
3. Show normalized findings
cat evidence/findings.json

Point out that all scanner outputs are normalized into one schema.

4. Show context-aware prioritization
cat evidence/prioritized-risk-register.md

Explain the contrast:

FIND-001 becomes P0 because the service is customer-facing, reachable, sensitive, and confirmed.
FIND-002 remains P2 because it is internal/dev/non-reachable.
FIND-003 is capped at P4 because validation classifies it as a likely test fixture.
5. Show the decision trace
cat evidence/decision-trace.md

Explain that the lab does not just output scores. It records the reasoning behind the decision.

6. Show remediation guidance
cat evidence/remediation-plan.md

Emphasize that remediation is recommendation-only and requires human approval.

7. Show evidence packaging
cat evidence/evidence-bundle.md

Explain that the output is designed for auditability, review, and executive communication.

Talk Track

Use this short version:

Continuum Lab demonstrates a local security reasoning loop. It takes scanner findings from Semgrep, Gitleaks, and a dependency-audit adapter, normalizes them, validates them inside a controlled lab boundary, enriches them with synthetic context, and produces prioritized evidence-backed remediation guidance.

The important point is that three scanner findings do not become three critical incidents. One becomes P0, one remains P2, and one is capped at P4 because context and validation change the operational decision.
Safety Boundaries

The lab must remain inside these boundaries:

No production targets
No external exploitation
No real credentials
No autonomous production remediation
No live cloud mutation
No runtime enforcement outside the local lab
No cloud APIs required
No customer data
No real database
Generated Artifacts
Artifact	Purpose
scanners/semgrep/semgrep-output.json	Raw Semgrep scanner output
scanners/gitleaks/gitleaks-output.json	Raw Gitleaks scanner output
scanners/dependency-audit/dependency-audit-output.json	Raw dependency-audit scanner output
evidence/findings.json	Normalized findings
evidence/validation-results.json	Lab-only validation evidence
evidence/prioritized-findings.json	Structured prioritized findings
evidence/prioritized-risk-register.md	Human-readable risk register
evidence/decision-trace.md	Reasoning trace
evidence/remediation-plan.md	Human-readable remediation plan
evidence/evidence-bundle.md	Human-readable evidence bundle
evidence/demo-summary.md	Executive-facing summary
Cleanup Commands

Remove a temporary clone:

cd /tmp
rm -rf continuum-lab

Stop the local vulnerable API if it was started manually:

cd ~/continuum-lab
docker compose down

Remove scanner containers/images only if desired:

docker image ls | grep -E "semgrep|gitleaks"

Do not delete committed evidence files from the repository unless intentionally regenerating and recommitting them.

Demo Success Criteria

The demo is successful when:

./run_demo.sh completes without error
Semgrep reports 1 finding
Gitleaks reports 1 finding
Dependency audit reports 1 finding
FIND-001 is P0
FIND-002 is P2
FIND-003 is P4
Evidence artifacts are generated
Remediation remains recommendation-only
Safety boundaries remain intact
v0.1 Completion Statement

Continuum Lab v0.1 is complete when the scanner triad, normalization, validation, prioritization, remediation recommendation, evidence bundle, executive summary, and demo checklist all run from a fresh clone with one command:

./run_demo.sh

