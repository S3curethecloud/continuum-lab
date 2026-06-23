# Decision Trace

Generated: 2026-06-23T04:40:06.688337+00:00

This file records why each finding received its priority.

## FIND-001 - P0

- Service: customer-api
- Severity: high
- Risk score: 100
- Validation: confirmed_in_lab

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

## FIND-002 - P2

- Service: admin-worker
- Severity: critical
- Risk score: 59
- Validation: unconfirmed

Decision reasons:

- +85: base severity is critical
- -8: environment is dev
- -5: service is not internet reachable
- -8: WAF or edge filtering is present
- -5: business criticality is tier_3
- +0: low-sensitivity data classification is test
- +0: validation status is unconfirmed

## FIND-003 - P4

- Service: customer-api
- Severity: medium
- Risk score: 25
- Validation: likely_test_fixture

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
- -25: validation status is likely_test_fixture
- cap: validation status likely_test_fixture limits score to 25
