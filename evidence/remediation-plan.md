# Remediation Plan

Generated: 2026-06-23T04:13:56.109756+00:00

## Scope

This remediation plan is generated for the local Continuum Lab only.

- Production change allowed: false
- External targeting allowed: false
- Cloud mutation allowed: false
- Automation boundary: recommendation only
- Human approval required: true

## Summary

- Total remediation items: 3

### Action States

| Action State | Count |
|---|---:|
| document_and_monitor | 1 |
| prepare_remediation_for_human_review | 1 |
| schedule_validation_and_remediation_review | 1 |

## Remediation Items

### FIND-001 - Replace unsafe query construction with parameterized query

- Priority: P0
- Risk score: 100
- Service: customer-api
- Type: sql_injection
- Validation status: confirmed_in_lab
- Action state: prepare_remediation_for_human_review
- Recommended change: Prepare a code patch that replaces string-built SQL with parameterized query execution.

Steps:

- Identify the vulnerable query construction path.
- Replace string interpolation or concatenation with parameterized query APIs.
- Add a regression test for expected safe query behavior.
- Rerun lab validation after patching.
- Rerun prioritization and evidence generation.

Post-change validation:

- Confirm the vulnerable route no longer accepts query-shaping input.
- Confirm regression tests pass.
- Confirm scanner output no longer reports the same finding.
- Confirm evidence bundle records before-and-after status.

Rollback:

- Revert the patch branch or commit if tests fail.
- Restore the previous lab image only inside the local lab environment.

Guardrails:

- Do not apply production code changes from this lab.
- Do not run exploit payloads against external targets.
- Keep validation inside local intentionally vulnerable services.

### FIND-002 - Review and upgrade vulnerable dependency

- Priority: P2
- Risk score: 59
- Service: admin-worker
- Type: vulnerable_dependency
- Validation status: unconfirmed
- Action state: schedule_validation_and_remediation_review
- Recommended change: Prepare a dependency upgrade plan and validate compatibility inside the lab.

Steps:

- Confirm the affected dependency is installed and used by the service.
- Check whether the vulnerable component is reachable in the lab context.
- Identify a safe patched version.
- Update the dependency manifest in a branch.
- Run unit tests and dependency scan again.

Post-change validation:

- Confirm dependency scanner no longer reports the same vulnerable version.
- Confirm service tests pass.
- Confirm no new high-priority dependency findings were introduced.

Rollback:

- Restore the previous dependency lockfile if the upgrade breaks compatibility.
- Document why the finding remains accepted if no safe upgrade exists.

Guardrails:

- Do not auto-upgrade production dependencies.
- Do not suppress dependency findings without owner approval.

### FIND-003 - Document likely test fixture

- Priority: P4
- Risk score: 25
- Service: customer-api
- Type: secret_detection
- Validation status: likely_test_fixture
- Action state: document_and_monitor
- Recommended change: Keep the finding low priority and document why it is treated as fixture/test data.

Steps:

- Confirm the file path is test-only or fixture-only.
- Confirm the detected value is not a real credential.
- Rename obvious fake secrets where practical to reduce scanner noise.
- Add a comment or fixture naming convention that clearly marks the sample as non-production.

Post-change validation:

- Rerun the secret scanner in the lab.
- Confirm the finding remains classified as non-production fixture evidence.

Rollback:

- Revert documentation or fixture naming changes if they break tests.

Guardrails:

- Do not rotate real credentials unless real credential exposure is confirmed.
- Do not target external systems.

