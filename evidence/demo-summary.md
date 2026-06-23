# Continuum Lab Demo Summary

Generated: 2026-06-23T04:43:32.828401+00:00

## Executive Summary

Continuum Lab is a safe, local, provider-neutral security reasoning lab. It emulates a modern security operating loop where local discovery findings are validated, enriched with context, prioritized by risk, mapped to remediation guidance, and packaged into evidence artifacts.

The current v0.1 lab demonstrates the following flow:

```text
local lab files
  -> normalized discovery findings
  -> lab-only validation
  -> context-aware prioritization
  -> remediation recommendation
  -> evidence bundle
```

## Safety Boundary

| Boundary | Status |
|---|---|
| Production targeting | Disabled |
| External targeting | Disabled |
| Cloud mutation | Disabled |
| Real credentials | Not used |
| Autonomous production remediation | Disabled |
| Human approval | Required for remediation decisions |

## Discovery Result

- Normalized findings discovered: 3
- Prioritized findings: 3

| Finding | Priority | Score | Service | Type | Validation | File |
|---|---|---:|---|---|---|---|
| FIND-001 | P0 | 100 | customer-api | sql_injection | confirmed_in_lab | apps/vulnerable-node-api/src/routes/search.js |
| FIND-002 | P2 | 59 | admin-worker | vulnerable_dependency | unconfirmed | apps/vulnerable-python-api/requirements.txt |
| FIND-003 | P4 | 25 | customer-api | secret_detection | likely_test_fixture | apps/vulnerable-node-api/test/fixtures/example.env |

## Priority Distribution

| Priority | Count |
|---|---:|
| P0 | 1 |
| P1 | 0 |
| P2 | 1 |
| P3 | 0 |
| P4 | 1 |

## Validation Distribution

| Validation Status | Count |
|---|---:|
| confirmed_in_lab | 1 |
| likely_test_fixture | 1 |
| unconfirmed | 1 |

## Why FIND-001 Is P0

- Finding: `FIND-001`
- Type: `sql_injection`
- Service: `customer-api`
- File: `apps/vulnerable-node-api/src/routes/search.js`
- Risk score: `100`
- Priority: `P0`
- Validation status: `confirmed_in_lab`

Decision factors:

- +70: base severity is high
- +10: environment is prod-like
- +15: service is internet reachable
- +10: service is in a production path
- +8: route or service is marked as not requiring auth
- +4: no WAF or edge filtering recorded
- +10: business criticality is tier_1
- +15: regulated data present
- +8: service identity is marked over-permissive
- +5: privilege level is high
- +5: scanner confidence is high
- +10: validation status is confirmed_in_lab

Validation evidence:

- Finding maps to customer-api
- Service is marked internet_reachable=true
- Service is marked production_path=true
- Finding type requires remediation review before any enforcement

## Recommended Remediation for FIND-001

- Title: Replace unsafe query construction with parameterized query
- Action state: `prepare_remediation_for_human_review`
- Recommended change: Prepare a code patch that replaces string-built SQL with parameterized query execution.

Recommended steps:

- Identify the vulnerable query construction path.
- Replace string interpolation or concatenation with parameterized query APIs.
- Add a regression test for expected safe query behavior.
- Rerun lab validation after patching.
- Rerun prioritization and evidence generation.

Rollback guidance:

- Revert the patch branch or commit if tests fail.
- Restore the previous lab image only inside the local lab environment.

## Generated Evidence Artifacts

| Artifact | Purpose |
|---|---|
| `evidence/findings.json` | Normalized local discovery output |
| `evidence/validation-results.json` | Lab-only validation evidence |
| `evidence/prioritized-findings.json` | Context-aware prioritized findings |
| `evidence/prioritized-risk-register.md` | Human-readable risk register |
| `evidence/decision-trace.md` | Full prioritization reasoning trace |
| `evidence/remediation-plan.json` | Structured remediation recommendations |
| `evidence/remediation-plan.md` | Human-readable remediation plan |
| `evidence/evidence-bundle.json` | Structured evidence bundle |
| `evidence/evidence-bundle.md` | Human-readable evidence bundle |
| `evidence/demo-summary.md` | Executive-facing demo summary |

## Demo Talking Points

- The lab shows that scanner findings alone are not enough.
- Context changes priority: reachability, production path, data sensitivity, business criticality, and compensating controls matter.
- Validation status can raise or cap risk.
- Remediation remains recommendation-only unless a controlled trust mode allows more.
- The current implementation is intentionally local-only and evidence-first.

## Recommended Next Phase

Add real scanner adapters while preserving the same normalized finding schema. Good next candidates:

- Semgrep adapter for SAST-style local code findings
- Gitleaks adapter for local secret scanning
- Trivy or npm audit adapter for dependency and container findings

The goal is to replace static marker discovery with real local scanner output while keeping validation, prioritization, remediation, and evidence generation unchanged.

