# Continuum Lab

A safe, local, provider-neutral lab for emulating a modern security reasoning loop:

Discovery -> Prioritization -> Validation -> Remediation -> Evidence

## Quick Links

- [Executive Demo Summary](evidence/demo-summary.md)
- [Prioritized Risk Register](evidence/prioritized-risk-register.md)
- [Remediation Plan](evidence/remediation-plan.md)
- [Evidence Bundle](evidence/evidence-bundle.md)

## Purpose

This lab is designed to study the next generation of security operations where scanner findings are enriched with environment context, validated safely, prioritized by business risk, and turned into evidence-backed remediation plans.

## Safety Boundaries

This lab is for local, controlled testing only.

- No production targets
- No external exploitation
- No real credentials
- No autonomous production remediation
- No live cloud mutation by default
- All validation must run inside controlled lab services

## Lab Phases

1. Discovery
2. Context enrichment
3. Risk prioritization
4. Safe validation
5. Remediation recommendation
6. Evidence generation
7. Trust-mode controls

## Directory Layout

```text
apps/          Intentionally vulnerable local demo apps
context/       Synthetic cloud, network, identity, and business context
scanners/      Scanner configuration and adapters
engine/        Reasoning, scoring, validation, and evidence scripts
evidence/      Generated findings, reports, and decision traces
policies/      Learn, assist, and lab-only enforce mode controls
Trust Modes
Mode	Behavior
learn	Generate findings and recommendations only
assist	Generate suggested patches or remediation plans for review
enforce-lab-only	Apply safe, reversible changes only inside the lab
Run the Lab
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
Current v0.1 Workflow
local lab files
  -> normalized discovery findings
  -> lab-only validation
  -> context-aware prioritization
  -> decision trace
  -> remediation plan
  -> evidence bundle
Local Vulnerable Node API

The first local lab service is:

apps/vulnerable-node-api/

It provides a local-only Express API for demonstrating unsafe SQL-style query construction.

Run it with:

docker compose up --build vulnerable-node-api

In another terminal, verify health:

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

The discovery phase uses a local static ingester:

python3 engine/ingest_findings.py

It inspects local lab files and generates:

evidence/findings.json

Current local discovery targets:

Finding	Source File	Purpose
FIND-001	apps/vulnerable-node-api/src/routes/search.js	Unsafe SQL-style query construction marker
FIND-002	apps/vulnerable-python-api/requirements.txt	Outdated dependency marker
FIND-003	apps/vulnerable-node-api/test/fixtures/example.env	Secret-like test fixture marker

The discovery ingester is local-only. It does not scan external systems, call cloud APIs, exploit targets, or mutate resources.

Remediation Phase

The remediation phase generates recommendation-only artifacts:

evidence/remediation-plan.json
evidence/remediation-plan.md

The remediation engine does not patch code, mutate cloud resources, target external systems, or perform autonomous production enforcement.

Status

v0.1 local discovery, validation, prioritization, remediation recommendation, and evidence generation are working.

## Demo Summary

The lab generates an executive-facing summary:

- `evidence/demo-summary.md`

This report summarizes the lab purpose, safety boundaries, discovery results, why `FIND-001` is prioritized as `P0`, remediation guidance, generated evidence artifacts, and recommended next phases.
