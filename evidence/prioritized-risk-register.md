# Prioritized Risk Register

Generated: 2026-06-23T04:24:23.998334+00:00

| Priority | Score | Finding | Severity | Service | Type | Validation | Summary |
|---|---:|---|---|---|---|---|---|
| P0 | 100 | FIND-001 | high | customer-api | sql_injection | confirmed_in_lab | +70: base severity is high; +10: environment is prod-like; +15: service is internet reachable; +10: service is in a production path |
| P2 | 59 | FIND-002 | critical | admin-worker | vulnerable_dependency | unconfirmed | +85: base severity is critical; -8: environment is dev; -5: service is not internet reachable; -8: WAF or edge filtering is present |
| P4 | 25 | FIND-003 | medium | customer-api | secret_detection | likely_test_fixture | +45: base severity is medium; +10: environment is prod-like; +15: service is internet reachable; +10: service is in a production path |

## Notes

- This report is generated from lab data only.
- Scores are context-aware and evidence-driven, not scanner-only.
- Validation and remediation must remain inside the controlled lab boundary.
