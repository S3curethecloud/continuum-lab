#!/usr/bin/env python3
"""
Continuum Lab v0.1 - Demo summary generator.

This script creates an executive-facing demo summary from generated lab evidence.
It does not scan, exploit, patch, target external systems, or mutate resources.
"""

from __future__ import annotations

import json
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


def normalize_findings(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict) and isinstance(raw.get("findings"), list):
        return raw["findings"]
    return []


def normalize_validation_results(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, dict) and isinstance(raw.get("results"), list):
        return raw["results"]
    return []


def normalize_remediation_items(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, dict) and isinstance(raw.get("items"), list):
        return raw["items"]
    return []


def find_item(items: list[dict[str, Any]], finding_id: str) -> dict[str, Any]:
    for item in items:
        if item.get("finding_id") == finding_id:
            return item
    return {}


def priority_sort_key(finding: dict[str, Any]) -> tuple[int, int]:
    priority = str(finding.get("priority", "P4"))
    score = int(finding.get("risk_score", 0))
    try:
        priority_index = PRIORITY_ORDER.index(priority)
    except ValueError:
        priority_index = len(PRIORITY_ORDER)
    return priority_index, -score


def count_by(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = str(item.get(key, "unknown"))
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def markdown_escape(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def finding_row(finding: dict[str, Any]) -> str:
    return "| {finding_id} | {priority} | {score} | {service} | {type_} | {validation} | {file} |".format(
        finding_id=markdown_escape(finding.get("finding_id", "")),
        priority=markdown_escape(finding.get("priority", "")),
        score=markdown_escape(finding.get("risk_score", "")),
        service=markdown_escape(finding.get("service", "")),
        type_=markdown_escape(finding.get("type", "")),
        validation=markdown_escape(finding.get("validation_status", "")),
        file=markdown_escape(finding.get("file", "")),
    )


def generate_summary() -> str:
    generated_at = datetime.now(timezone.utc).isoformat()

    raw_findings = load_json(EVIDENCE_DIR / "findings.json", {})
    prioritized = normalize_findings(load_json(EVIDENCE_DIR / "prioritized-findings.json", []))
    validations = normalize_validation_results(load_json(EVIDENCE_DIR / "validation-results.json", {}))
    remediation_items = normalize_remediation_items(load_json(EVIDENCE_DIR / "remediation-plan.json", {}))

    prioritized = sorted(prioritized, key=priority_sort_key)

    priority_counts = count_by(prioritized, "priority")
    validation_counts = count_by(prioritized, "validation_status")

    find_001 = find_item(prioritized, "FIND-001")
    remediate_001 = find_item(remediation_items, "FIND-001")
    validation_001 = find_item(validations, "FIND-001")

    lines: list[str] = [
        "# Continuum Lab Demo Summary",
        "",
        f"Generated: {generated_at}",
        "",
        "## Executive Summary",
        "",
        "Continuum Lab is a safe, local, provider-neutral security reasoning lab. It emulates a modern security operating loop where local discovery findings are validated, enriched with context, prioritized by risk, mapped to remediation guidance, and packaged into evidence artifacts.",
        "",
        "The current v0.1 lab demonstrates the following flow:",
        "",
        "```text",
        "local lab files",
        "  -> normalized discovery findings",
        "  -> lab-only validation",
        "  -> context-aware prioritization",
        "  -> remediation recommendation",
        "  -> evidence bundle",
        "```",
        "",
        "## Safety Boundary",
        "",
        "| Boundary | Status |",
        "|---|---|",
        "| Production targeting | Disabled |",
        "| External targeting | Disabled |",
        "| Cloud mutation | Disabled |",
        "| Real credentials | Not used |",
        "| Autonomous production remediation | Disabled |",
        "| Human approval | Required for remediation decisions |",
        "",
        "## Discovery Result",
        "",
        f"- Normalized findings discovered: {len(raw_findings.get('findings', [])) if isinstance(raw_findings, dict) else len(prioritized)}",
        f"- Prioritized findings: {len(prioritized)}",
        "",
        "| Finding | Priority | Score | Service | Type | Validation | File |",
        "|---|---|---:|---|---|---|---|",
    ]

    for finding in prioritized:
        lines.append(finding_row(finding))

    lines.extend(
        [
            "",
            "## Priority Distribution",
            "",
            "| Priority | Count |",
            "|---|---:|",
        ]
    )

    for priority in PRIORITY_ORDER:
        lines.append(f"| {priority} | {priority_counts.get(priority, 0)} |")

    lines.extend(
        [
            "",
            "## Validation Distribution",
            "",
            "| Validation Status | Count |",
            "|---|---:|",
        ]
    )

    for status, count in validation_counts.items():
        lines.append(f"| {markdown_escape(status)} | {count} |")

    lines.extend(
        [
            "",
            "## Why FIND-001 Is P0",
            "",
        ]
    )

    if find_001:
        lines.extend(
            [
                f"- Finding: `{find_001.get('finding_id')}`",
                f"- Type: `{find_001.get('type')}`",
                f"- Service: `{find_001.get('service')}`",
                f"- File: `{find_001.get('file')}`",
                f"- Risk score: `{find_001.get('risk_score')}`",
                f"- Priority: `{find_001.get('priority')}`",
                f"- Validation status: `{find_001.get('validation_status')}`",
                "",
                "Decision factors:",
                "",
            ]
        )

        for reason in find_001.get("decision_reasons", []):
            lines.append(f"- {reason}")

        if validation_001:
            lines.extend(["", "Validation evidence:", ""])
            for item in validation_001.get("evidence", []):
                lines.append(f"- {item}")
    else:
        lines.append("FIND-001 was not present in the current prioritized findings output.")

    lines.extend(
        [
            "",
            "## Recommended Remediation for FIND-001",
            "",
        ]
    )

    if remediate_001:
        lines.extend(
            [
                f"- Title: {remediate_001.get('title')}",
                f"- Action state: `{remediate_001.get('action_state')}`",
                f"- Recommended change: {remediate_001.get('recommended_change')}",
                "",
                "Recommended steps:",
                "",
            ]
        )

        for step in remediate_001.get("steps", []):
            lines.append(f"- {step}")

        lines.extend(["", "Rollback guidance:", ""])

        for rollback in remediate_001.get("rollback", []):
            lines.append(f"- {rollback}")
    else:
        lines.append("No remediation plan entry was found for FIND-001.")

    lines.extend(
        [
            "",
            "## Generated Evidence Artifacts",
            "",
            "| Artifact | Purpose |",
            "|---|---|",
            "| `evidence/findings.json` | Normalized local discovery output |",
            "| `evidence/validation-results.json` | Lab-only validation evidence |",
            "| `evidence/prioritized-findings.json` | Context-aware prioritized findings |",
            "| `evidence/prioritized-risk-register.md` | Human-readable risk register |",
            "| `evidence/decision-trace.md` | Full prioritization reasoning trace |",
            "| `evidence/remediation-plan.json` | Structured remediation recommendations |",
            "| `evidence/remediation-plan.md` | Human-readable remediation plan |",
            "| `evidence/evidence-bundle.json` | Structured evidence bundle |",
            "| `evidence/evidence-bundle.md` | Human-readable evidence bundle |",
            "| `evidence/demo-summary.md` | Executive-facing demo summary |",
            "",
            "## Demo Talking Points",
            "",
            "- The lab shows that scanner findings alone are not enough.",
            "- Context changes priority: reachability, production path, data sensitivity, business criticality, and compensating controls matter.",
            "- Validation status can raise or cap risk.",
            "- Remediation remains recommendation-only unless a controlled trust mode allows more.",
            "- The current implementation is intentionally local-only and evidence-first.",
            "",
            "## Recommended Next Phase",
            "",
            "Add real scanner adapters while preserving the same normalized finding schema. Good next candidates:",
            "",
            "- Semgrep adapter for SAST-style local code findings",
            "- Gitleaks adapter for local secret scanning",
            "- Trivy or npm audit adapter for dependency and container findings",
            "",
            "The goal is to replace static marker discovery with real local scanner output while keeping validation, prioritization, remediation, and evidence generation unchanged.",
            "",
        ]
    )

    return "\n".join(lines)


def main() -> None:
    output = generate_summary()
    path = EVIDENCE_DIR / "demo-summary.md"
    path.write_text(output + "\n", encoding="utf-8")

    print(f"Wrote {path}")


if __name__ == "__main__":
    main()
