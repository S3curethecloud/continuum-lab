#!/usr/bin/env python3
"""
Continuum Lab v0.1 - Remediation recommendation engine.

This script reads prioritized findings and produces lab-safe remediation plans.
It does not patch code, mutate cloud resources, target external systems, or
perform autonomous enforcement.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = ROOT / "evidence"

PRIORITY_ORDER = ["P0", "P1", "P2", "P3", "P4"]


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default

    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return default

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def normalize_findings(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict) and isinstance(raw.get("findings"), list):
        return raw["findings"]
    return []


def priority_sort_key(finding: dict[str, Any]) -> tuple[int, int]:
    priority = str(finding.get("priority", "P4"))
    score = int(finding.get("risk_score", 0))
    try:
        priority_index = PRIORITY_ORDER.index(priority)
    except ValueError:
        priority_index = len(PRIORITY_ORDER)
    return priority_index, -score


def action_state(priority: str, validation_status: str) -> str:
    validation_status = validation_status.lower()

    if validation_status in {"false_positive", "not_reproducible"}:
        return "no_action_record_only"

    if validation_status in {"likely_test_fixture", "test_fixture"}:
        return "document_and_monitor"

    if priority in {"P0", "P1"} and validation_status in {"confirmed", "confirmed_in_lab", "validated"}:
        return "prepare_remediation_for_human_review"

    if priority in {"P0", "P1"}:
        return "validate_before_remediation"

    if priority == "P2":
        return "schedule_validation_and_remediation_review"

    return "backlog_or_monitor"


def remediation_template(finding: dict[str, Any]) -> dict[str, Any]:
    finding_type = str(finding.get("type", "unknown"))
    priority = str(finding.get("priority", "P4"))
    validation_status = str(finding.get("validation_status", "pending_validation"))
    state = action_state(priority, validation_status)

    base = {
        "finding_id": finding.get("finding_id", "unknown"),
        "priority": priority,
        "risk_score": finding.get("risk_score", 0),
        "service": finding.get("service", "unknown-service"),
        "type": finding_type,
        "validation_status": validation_status,
        "action_state": state,
        "requires_human_approval": True,
        "production_change_allowed": False,
        "external_targeting": False,
        "cloud_mutation": False,
        "automation_boundary": "recommendation_only",
    }

    if state == "no_action_record_only":
        base.update(
            {
                "title": "Record non-actionable finding",
                "recommended_change": "Do not remediate unless new evidence changes the validation status.",
                "steps": [
                    "Record the validation result in the evidence bundle.",
                    "Keep the original scanner finding for traceability.",
                    "Reopen only if new context or validation evidence appears."
                ],
                "post_change_validation": [
                    "No remediation validation required while finding remains non-actionable."
                ],
                "rollback": [
                    "No runtime or code change was made."
                ],
                "guardrails": [
                    "Do not mutate systems for non-actionable findings.",
                    "Do not suppress future findings globally without owner review."
                ],
            }
        )
        return base

    if state == "document_and_monitor":
        base.update(
            {
                "title": "Document likely test fixture",
                "recommended_change": "Keep the finding low priority and document why it is treated as fixture/test data.",
                "steps": [
                    "Confirm the file path is test-only or fixture-only.",
                    "Confirm the detected value is not a real credential.",
                    "Rename obvious fake secrets where practical to reduce scanner noise.",
                    "Add a comment or fixture naming convention that clearly marks the sample as non-production."
                ],
                "post_change_validation": [
                    "Rerun the secret scanner in the lab.",
                    "Confirm the finding remains classified as non-production fixture evidence."
                ],
                "rollback": [
                    "Revert documentation or fixture naming changes if they break tests."
                ],
                "guardrails": [
                    "Do not rotate real credentials unless real credential exposure is confirmed.",
                    "Do not target external systems."
                ],
            }
        )
        return base

    if finding_type == "sql_injection":
        base.update(
            {
                "title": "Replace unsafe query construction with parameterized query",
                "recommended_change": "Prepare a code patch that replaces string-built SQL with parameterized query execution.",
                "steps": [
                    "Identify the vulnerable query construction path.",
                    "Replace string interpolation or concatenation with parameterized query APIs.",
                    "Add a regression test for expected safe query behavior.",
                    "Rerun lab validation after patching.",
                    "Rerun prioritization and evidence generation."
                ],
                "post_change_validation": [
                    "Confirm the vulnerable route no longer accepts query-shaping input.",
                    "Confirm regression tests pass.",
                    "Confirm scanner output no longer reports the same finding.",
                    "Confirm evidence bundle records before-and-after status."
                ],
                "rollback": [
                    "Revert the patch branch or commit if tests fail.",
                    "Restore the previous lab image only inside the local lab environment."
                ],
                "guardrails": [
                    "Do not apply production code changes from this lab.",
                    "Do not run exploit payloads against external targets.",
                    "Keep validation inside local intentionally vulnerable services."
                ],
            }
        )
        return base

    if finding_type == "vulnerable_dependency":
        base.update(
            {
                "title": "Review and upgrade vulnerable dependency",
                "recommended_change": "Prepare a dependency upgrade plan and validate compatibility inside the lab.",
                "steps": [
                    "Confirm the affected dependency is installed and used by the service.",
                    "Check whether the vulnerable component is reachable in the lab context.",
                    "Identify a safe patched version.",
                    "Update the dependency manifest in a branch.",
                    "Run unit tests and dependency scan again."
                ],
                "post_change_validation": [
                    "Confirm dependency scanner no longer reports the same vulnerable version.",
                    "Confirm service tests pass.",
                    "Confirm no new high-priority dependency findings were introduced."
                ],
                "rollback": [
                    "Restore the previous dependency lockfile if the upgrade breaks compatibility.",
                    "Document why the finding remains accepted if no safe upgrade exists."
                ],
                "guardrails": [
                    "Do not auto-upgrade production dependencies.",
                    "Do not suppress dependency findings without owner approval."
                ],
            }
        )
        return base

    if finding_type == "secret_detection":
        base.update(
            {
                "title": "Confirm and remove exposed secret-like material",
                "recommended_change": "Determine whether the value is real. If real in the lab, rotate only lab credentials and remove the secret from tracked files.",
                "steps": [
                    "Confirm whether the detected value is real or a fixture.",
                    "If real lab credential exposure is confirmed, rotate the lab credential.",
                    "Remove the value from tracked files.",
                    "Add a safe placeholder value.",
                    "Rerun secret scanning."
                ],
                "post_change_validation": [
                    "Confirm the scanner no longer detects real secret material.",
                    "Confirm the application uses environment variables or a safe lab secret source.",
                    "Record the rotation evidence if a lab credential was rotated."
                ],
                "rollback": [
                    "Restore a safe placeholder if application tests require the variable.",
                    "Do not restore real secrets into Git history."
                ],
                "guardrails": [
                    "Do not rotate production credentials from this lab.",
                    "Do not test detected secrets against external services."
                ],
            }
        )
        return base

    base.update(
        {
            "title": "Prepare generic remediation review",
            "recommended_change": "Review the finding with service owner and define a lab-safe remediation plan.",
            "steps": [
                "Confirm service ownership.",
                "Confirm reachability and business impact.",
                "Define a safe remediation path.",
                "Run lab-only validation before and after the change."
            ],
            "post_change_validation": [
                "Rerun validation, prioritization, and evidence generation."
            ],
            "rollback": [
                "Revert lab-only changes if validation fails."
            ],
            "guardrails": [
                "Do not mutate production systems.",
                "Do not target external systems."
            ],
        }
    )
    return base


def build_summary(plans: list[dict[str, Any]]) -> dict[str, Any]:
    by_priority = Counter(plan["priority"] for plan in plans)
    by_state = Counter(plan["action_state"] for plan in plans)
    by_type = Counter(plan["type"] for plan in plans)

    return {
        "total_remediation_items": len(plans),
        "by_priority": {p: by_priority.get(p, 0) for p in PRIORITY_ORDER},
        "by_action_state": dict(sorted(by_state.items())),
        "by_type": dict(sorted(by_type.items())),
        "production_change_allowed": False,
        "external_targeting": False,
        "cloud_mutation": False,
    }


def markdown_escape(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def generate_markdown(plan: dict[str, Any]) -> str:
    lines = [
        "# Remediation Plan",
        "",
        f"Generated: {plan['generated_at']}",
        "",
        "## Scope",
        "",
        "This remediation plan is generated for the local Continuum Lab only.",
        "",
        "- Production change allowed: false",
        "- External targeting allowed: false",
        "- Cloud mutation allowed: false",
        "- Automation boundary: recommendation only",
        "- Human approval required: true",
        "",
        "## Summary",
        "",
        f"- Total remediation items: {plan['summary']['total_remediation_items']}",
        "",
        "### Action States",
        "",
        "| Action State | Count |",
        "|---|---:|",
    ]

    for state, count in plan["summary"]["by_action_state"].items():
        lines.append(f"| {markdown_escape(state)} | {count} |")

    lines.extend(
        [
            "",
            "## Remediation Items",
            "",
        ]
    )

    for item in plan["items"]:
        lines.extend(
            [
                f"### {item['finding_id']} - {item['title']}",
                "",
                f"- Priority: {item['priority']}",
                f"- Risk score: {item['risk_score']}",
                f"- Service: {item['service']}",
                f"- Type: {item['type']}",
                f"- Validation status: {item['validation_status']}",
                f"- Action state: {item['action_state']}",
                f"- Recommended change: {item['recommended_change']}",
                "",
                "Steps:",
                "",
            ]
        )

        for step in item["steps"]:
            lines.append(f"- {step}")

        lines.extend(["", "Post-change validation:", ""])

        for check in item["post_change_validation"]:
            lines.append(f"- {check}")

        lines.extend(["", "Rollback:", ""])

        for rollback in item["rollback"]:
            lines.append(f"- {rollback}")

        lines.extend(["", "Guardrails:", ""])

        for guardrail in item["guardrails"]:
            lines.append(f"- {guardrail}")

        lines.append("")

    return "\n".join(lines)


def main() -> None:
    findings = normalize_findings(load_json(EVIDENCE_DIR / "prioritized-findings.json", []))
    findings = sorted(findings, key=priority_sort_key)

    items = [remediation_template(finding) for finding in findings]
    generated_at = datetime.now(timezone.utc).isoformat()

    plan = {
        "schema": "continuum-lab-remediation-plan/v0.1",
        "generated_at": generated_at,
        "scope": {
            "environment": "local_lab_only",
            "production_change_allowed": False,
            "external_targeting": False,
            "cloud_mutation": False,
            "automation_boundary": "recommendation_only",
            "human_approval_required": True,
        },
        "summary": build_summary(items),
        "items": items,
    }

    write_json(EVIDENCE_DIR / "remediation-plan.json", plan)
    (EVIDENCE_DIR / "remediation-plan.md").write_text(
        generate_markdown(plan) + "\n",
        encoding="utf-8",
    )

    print(f"Generated remediation plan for {len(items)} findings.")
    print(f"Wrote {EVIDENCE_DIR / 'remediation-plan.json'}")
    print(f"Wrote {EVIDENCE_DIR / 'remediation-plan.md'}")


if __name__ == "__main__":
    main()
