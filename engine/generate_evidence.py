#!/usr/bin/env python3
"""
Continuum Lab v0.1 - Evidence bundle generator.

This script reads prioritized findings and produces demo-ready evidence
artifacts for review. It does not scan, exploit, validate, patch, or mutate
anything.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = ROOT / "evidence"
POLICIES_DIR = ROOT / "policies"

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


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8").strip()


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


def recommended_action(finding: dict[str, Any]) -> str:
    priority = str(finding.get("priority", "P4"))
    validation_status = str(finding.get("validation_status", "pending_validation")).lower()
    finding_type = str(finding.get("type", "unknown"))

    if validation_status in {"false_positive", "not_reproducible"}:
        return "Record as non-actionable unless new evidence appears."

    if validation_status in {"likely_test_fixture", "test_fixture"}:
        return "Keep as low priority, document fixture status, and ensure test secrets cannot be mistaken for real secrets."

    if priority in {"P0", "P1"} and validation_status in {"pending_validation", "unconfirmed"}:
        return "Run lab-only validation before remediation. Do not apply production changes."

    if priority in {"P0", "P1"} and validation_status in {"confirmed", "confirmed_in_lab", "validated"}:
        if finding_type == "sql_injection":
            return "Prepare parameterized query patch, add regression test, and rerun validation in the lab."
        if finding_type == "vulnerable_dependency":
            return "Prepare dependency upgrade plan, run tests, and compare scanner output before and after."
        if finding_type == "secret_detection":
            return "Confirm whether the secret is real, rotate only lab credentials if applicable, and remove unsafe material."
        return "Prepare remediation plan and rerun validation in the lab."

    if priority == "P2":
        return "Validate reachability and usage in the lab, then schedule remediation if confirmed."

    if priority == "P3":
        return "Track as backlog unless validation or exposure changes."

    return "Document evidence and monitor for context changes."


def build_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    by_priority = Counter(str(f.get("priority", "P4")) for f in findings)
    by_validation = Counter(str(f.get("validation_status", "pending_validation")) for f in findings)
    by_service = Counter(str(f.get("service", "unknown-service")) for f in findings)

    top_findings = sorted(findings, key=priority_sort_key)[:5]

    return {
        "total_findings": len(findings),
        "by_priority": {p: by_priority.get(p, 0) for p in PRIORITY_ORDER},
        "by_validation_status": dict(sorted(by_validation.items())),
        "by_service": dict(sorted(by_service.items())),
        "top_findings": [
            {
                "finding_id": f.get("finding_id"),
                "priority": f.get("priority"),
                "risk_score": f.get("risk_score"),
                "service": f.get("service"),
                "type": f.get("type"),
                "validation_status": f.get("validation_status", "pending_validation"),
            }
            for f in top_findings
        ],
    }


def markdown_escape(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def generate_markdown(bundle: dict[str, Any]) -> str:
    summary = bundle["summary"]
    findings = bundle["findings"]
    generated_at = bundle["generated_at"]

    lines = [
        "# Continuum Lab Evidence Bundle",
        "",
        f"Generated: {generated_at}",
        "",
        "## Scope",
        "",
        "This evidence bundle was generated from local lab data only.",
        "",
        "- No production systems were targeted.",
        "- No external targets were scanned.",
        "- No real credentials were used.",
        "- No cloud resources were mutated.",
        "- No autonomous production remediation was performed.",
        "",
        "## Executive Summary",
        "",
        f"- Total findings: {summary['total_findings']}",
        f"- P0 findings: {summary['by_priority'].get('P0', 0)}",
        f"- P1 findings: {summary['by_priority'].get('P1', 0)}",
        f"- P2 findings: {summary['by_priority'].get('P2', 0)}",
        f"- P3 findings: {summary['by_priority'].get('P3', 0)}",
        f"- P4 findings: {summary['by_priority'].get('P4', 0)}",
        "",
        "## Priority Distribution",
        "",
        "| Priority | Count |",
        "|---|---:|",
    ]

    for priority in PRIORITY_ORDER:
        lines.append(f"| {priority} | {summary['by_priority'].get(priority, 0)} |")

    lines.extend(
        [
            "",
            "## Validation Status Distribution",
            "",
            "| Validation Status | Count |",
            "|---|---:|",
        ]
    )

    for status, count in summary["by_validation_status"].items():
        lines.append(f"| {markdown_escape(status)} | {count} |")

    lines.extend(
        [
            "",
            "## Service Distribution",
            "",
            "| Service | Count |",
            "|---|---:|",
        ]
    )

    for service, count in summary["by_service"].items():
        lines.append(f"| {markdown_escape(service)} | {count} |")

    lines.extend(
        [
            "",
            "## Findings",
            "",
        ]
    )

    for finding in findings:
        lines.extend(
            [
                f"### {finding.get('finding_id', 'unknown')} - {finding.get('priority', 'P4')}",
                "",
                f"- Service: {finding.get('service', 'unknown-service')}",
                f"- Type: {finding.get('type', 'unknown')}",
                f"- Severity: {finding.get('severity', 'unknown')}",
                f"- Risk score: {finding.get('risk_score', 0)}",
                f"- Validation status: {finding.get('validation_status', 'pending_validation')}",
                f"- Source: {finding.get('source', 'unknown')}",
                f"- File: {finding.get('file', 'unknown')}",
                f"- Recommended action: {finding.get('recommended_action', 'Document and review.')}",
                "",
                "Decision reasons:",
                "",
            ]
        )

        for reason in finding.get("decision_reasons", []):
            lines.append(f"- {reason}")

        description = finding.get("description")
        if description:
            lines.extend(["", f"Description: {description}", ""])

    lines.extend(
        [
            "",
            "## Trust Boundary",
            "",
            "The lab currently supports evidence generation and recommendation workflows only.",
            "",
            "| Capability | Status |",
            "|---|---|",
            "| Discovery input | Lab data only |",
            "| Context enrichment | Enabled |",
            "| Prioritization | Enabled |",
            "| Validation | Not executed by this script |",
            "| Remediation | Recommendation only |",
            "| Cloud mutation | Disabled |",
            "| External targeting | Disabled |",
            "| Production enforcement | Disabled |",
            "",
        ]
    )

    return "\n".join(lines)


def main() -> None:
    findings = normalize_findings(load_json(EVIDENCE_DIR / "prioritized-findings.json", []))
    findings = sorted(findings, key=priority_sort_key)

    enriched_findings = []
    for finding in findings:
        enriched = dict(finding)
        enriched["recommended_action"] = recommended_action(enriched)
        enriched_findings.append(enriched)

    generated_at = datetime.now(timezone.utc).isoformat()

    bundle = {
        "schema": "continuum-lab-evidence-bundle/v0.1",
        "generated_at": generated_at,
        "scope": {
            "environment": "local_lab_only",
            "external_targeting": False,
            "cloud_mutation": False,
            "production_enforcement": False,
            "real_credentials": False,
        },
        "policy_files": {
            "learn": read_text(POLICIES_DIR / "learn-mode.yaml"),
            "assist": read_text(POLICIES_DIR / "assist-mode.yaml"),
            "enforce_lab_only": read_text(POLICIES_DIR / "enforce-mode-lab-only.yaml"),
        },
        "summary": build_summary(enriched_findings),
        "findings": enriched_findings,
    }

    write_json(EVIDENCE_DIR / "evidence-bundle.json", bundle)
    (EVIDENCE_DIR / "evidence-bundle.md").write_text(
        generate_markdown(bundle) + "\n",
        encoding="utf-8",
    )

    print(f"Generated evidence bundle for {len(enriched_findings)} findings.")
    print(f"Wrote {EVIDENCE_DIR / 'evidence-bundle.json'}")
    print(f"Wrote {EVIDENCE_DIR / 'evidence-bundle.md'}")


if __name__ == "__main__":
    main()
