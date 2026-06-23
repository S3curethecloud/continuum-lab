# Continuum Lab

A safe, local, provider-neutral lab for emulating a modern security reasoning loop:

Discovery -> Prioritization -> Validation -> Remediation -> Evidence

## Quick Links

- [Executive Demo Summary](evidence/demo-summary.md)
- [Prioritized Risk Register](evidence/prioritized-risk-register.md)
- [Remediation Plan](evidence/remediation-plan.md)
- [Evidence Bundle](evidence/evidence-bundle.md)

## Purpose

This lab studies the next generation of security operations where scanner findings are enriched with environment context, validated safely, prioritized by business risk, mapped to remediation guidance, and packaged into evidence-backed artifacts.

## Safety Boundaries

This lab is for local, controlled testing only.

- No production targets
- No external exploitation
- No real credentials
- No autonomous production remediation
- No live cloud mutation by default
- All validation must run inside controlled lab services

## Current v0.1 Workflow

```text
local scanner outputs and lab files
  -> normalized discovery findings
  -> lab-only validation
  -> context-aware prioritization
  -> remediation recommendation
  -> evidence bundle
  -> executive demo summary
Run the Full Demo

Run all scanner adapters and the full reasoning/evidence pipeline:

./run_demo.sh

This runs:

Semgrep SAST adapter
Gitleaks secret scanning adapter
Dependency-audit adapter
Discovery ingestion
Lab-only validation
Context-aware prioritization
Remediation recommendation
Evidence generation
Executive demo summary generation
Run Scanners Only
./run_scanners.sh

This generates:

scanners/semgrep/semgrep-output.json
scanners/gitleaks/gitleaks-output.json
scanners/dependency-audit/dependency-audit-output.json
Run Reasoning and Evidence Pipeline Only
./run_lab.sh

This generates:

evidence/findings.json
evidence/validation-results.json
evidence/prioritized-findings.json
evidence/prioritized-risk-register.md
evidence/decision-trace.md
evidence/remediation-plan.json
evidence/remediation-plan.md
evidence/evidence-bundle.json
evidence/evidence-bundle.md
evidence/demo-summary.md
Scanner Adapter Triad
Scanner Adapter	Finding	Expected Outcome	Purpose
Semgrep	FIND-001	P0	SAST finding escalates because it is customer-facing, reachable, sensitive, and validated
Dependency audit	FIND-002	P2	Critical dependency stays below P0 because it is dev/internal/non-reachable
Gitleaks	FIND-003	P4	Secret-like scanner hit is capped because validation classifies it as a likely test fixture
Directory Layout
apps/          Intentionally vulnerable local demo apps
context/       Synthetic cloud, network, identity, and business context
scanners/      Scanner configuration, runners, and raw scanner outputs
engine/        Ingestion, validation, prioritization, remediation, and evidence scripts
evidence/      Generated findings, reports, summaries, and decision traces
policies/      Learn, assist, and lab-only enforce mode controls
Trust Modes
Mode	Behavior
learn	Generate findings and recommendations only
assist	Generate suggested patches or remediation plans for review
enforce-lab-only	Apply safe, reversible changes only inside the lab
Local Vulnerable Node API

The first local lab service is:

apps/vulnerable-node-api/

It provides a local-only Express API for demonstrating unsafe SQL-style query construction.

Run it with:

docker compose up --build vulnerable-node-api

Verify health:

curl http://127.0.0.1:3001/health

Example local search route:

curl "http://127.0.0.1:3001/api/customers/search?q=Ada"

Safety boundaries:

Local-only Docker service
No real database
No real customer data
No real credentials
No external targets
No production remediation
Discovery Phase

The discovery phase uses engine/ingest_findings.py to normalize scanner outputs and local lab findings into one schema:

python3 engine/ingest_findings.py

Current discovery sources:

Source	Output
Semgrep	scanners/semgrep/semgrep-output.json
Gitleaks	scanners/gitleaks/gitleaks-output.json
Dependency audit	scanners/dependency-audit/dependency-audit-output.json
Static fallback	Local lab marker discovery when scanner output is missing
Semgrep SAST Adapter

Rule file:

scanners/semgrep/rules/continuum-lab-sast.yml

Run:

./scanners/semgrep/run_semgrep.sh

Expected normalized result:

Semgrep -> FIND-001 -> P0
Gitleaks Secret Scanning Adapter

Config file:

scanners/gitleaks/gitleaks.toml

Run:

./scanners/gitleaks/run_gitleaks.sh

Expected normalized result:

Gitleaks -> FIND-003 -> P4

The validation layer classifies the fake fixture secret as likely_test_fixture, and prioritization caps the risk score.

Dependency Scanning Adapter

Runner:

./scanners/dependency-audit/run_dependency_audit.sh

Expected normalized result:

Dependency audit -> FIND-002 -> P2

The finding remains P2 instead of P0 because context shows the affected service is dev, internal, not internet reachable, and protected by compensating controls.

Remediation Phase

The remediation phase generates recommendation-only artifacts:

evidence/remediation-plan.json
evidence/remediation-plan.md

The remediation engine does not patch code, mutate cloud resources, target external systems, or perform autonomous production enforcement.

Demo Summary

The lab generates an executive-facing summary:

evidence/demo-summary.md

This report summarizes the lab purpose, safety boundaries, discovery results, why FIND-001 is prioritized as P0, why other findings are not escalated, remediation guidance, generated evidence artifacts, and recommended next phases.

Status

v0.1 scanner triad, local discovery ingestion, validation, prioritization, remediation recommendation, evidence generation, and executive demo summary are working.
