# Continuum Lab Evidence Bundle

Generated: 2026-06-23T04:20:31.182205+00:00

## Scope

This evidence bundle was generated from local lab data only.

- No production systems were targeted.
- No external targets were scanned.
- No real credentials were used.
- No cloud resources were mutated.
- No autonomous production remediation was performed.

## Executive Summary

- Total findings: 3
- P0 findings: 1
- P1 findings: 0
- P2 findings: 1
- P3 findings: 0
- P4 findings: 1

## Priority Distribution

| Priority | Count |
|---|---:|
| P0 | 1 |
| P1 | 0 |
| P2 | 1 |
| P3 | 0 |
| P4 | 1 |

## Validation Status Distribution

| Validation Status | Count |
|---|---:|
| confirmed_in_lab | 1 |
| likely_test_fixture | 1 |
| unconfirmed | 1 |

## Service Distribution

| Service | Count |
|---|---:|
| admin-worker | 1 |
| customer-api | 2 |

## Findings

### FIND-001 - P0

- Service: customer-api
- Type: sql_injection
- Severity: high
- Risk score: 100
- Validation status: confirmed_in_lab
- Source: semgrep
- File: apps/vulnerable-node-api/src/routes/search.js
- Recommended action: Prepare parameterized query patch, add regression test, and rerun validation in the lab.

Decision reasons:

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

Description: Potential unsafe query construction in customer search route.

### FIND-002 - P2

- Service: admin-worker
- Type: vulnerable_dependency
- Severity: critical
- Risk score: 59
- Validation status: unconfirmed
- Source: trivy
- File: apps/vulnerable-python-api/requirements.txt
- Recommended action: Validate reachability and usage in the lab, then schedule remediation if confirmed.

Decision reasons:

- +85: base severity is critical
- -8: environment is dev
- -5: service is not internet reachable
- -8: WAF or edge filtering is present
- -5: business criticality is tier_3
- +0: low-sensitivity data classification is test
- +0: validation status is unconfirmed

Description: Critical dependency finding in a dev-only internal worker.

### FIND-003 - P4

- Service: customer-api
- Type: secret_detection
- Severity: medium
- Risk score: 25
- Validation status: likely_test_fixture
- Source: gitleaks
- File: apps/vulnerable-node-api/test/fixtures/example.env
- Recommended action: Keep as low priority, document fixture status, and ensure test secrets cannot be mistaken for real secrets.

Decision reasons:

- +45: base severity is medium
- +10: environment is prod-like
- +15: service is internet reachable
- +10: service is in a production path
- +8: route or service is marked as not requiring auth
- +4: no WAF or edge filtering recorded
- +10: business criticality is tier_1
- +15: regulated data present
- +8: service identity is marked over-permissive
- +5: privilege level is high
- -5: scanner confidence is low
- -25: validation status is likely_test_fixture
- cap: validation status likely_test_fixture limits score to 25

Description: Secret-like string appears in a test fixture.


## Trust Boundary

The lab currently supports evidence generation and recommendation workflows only.

| Capability | Status |
|---|---|
| Discovery input | Lab data only |
| Context enrichment | Enabled |
| Prioritization | Enabled |
| Validation | Not executed by this script |
| Remediation | Recommendation only |
| Cloud mutation | Disabled |
| External targeting | Disabled |
| Production enforcement | Disabled |

