#!/usr/bin/env python3
"""
Continuum Lab v0.1 - Context-aware prioritization engine.

This script does not scan, exploit, or mutate anything.
It reads normalized findings and synthetic lab context, then produces
evidence-backed priority decisions.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONTEXT_DIR = ROOT / "context"
EVIDENCE_DIR = ROOT / "evidence"

SEVERITY_BASE_SCORE = {
    "critical": 85,
    "high": 70,
    "medium": 45,
    "low": 20,
    "info": 5,
    "informational": 5,
}

PRIORITY_THRESHOLDS = [
    ("P0", 90),
    ("P1", 75),
    ("P2", 55),
    ("P3", 30),
    ("P4", 0),
]


def load_json(path: Path, default: Any) -> Any:
    """Load JSON safely. Empty files return the provided default."""
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
    if isinstance(raw, dict) and isinstance(raw.get("findings"), list):
        return raw["findings"]

    if isinstance(raw, list):
        return raw

    return []


def index_services(raw: Any, value_key: str | None = None) -> dict[str, dict[str, Any]]:
    """
    Accept either:
      {"services": [{"service": "name", ...}]}
      [{"service": "name", ...}]
      {"service-name": {...}}
      {"service-name": "tier_1"} with value_key="criticality"
    """
    indexed: dict[str, dict[str, Any]] = {}

    if isinstance(raw, dict) and isinstance(raw.get("services"), list):
        items = raw["services"]
    elif isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict):
        items = []
        for service, value in raw.items():
            if isinstance(value, dict):
                item = {"service": service, **value}
            else:
                item = {"service": service, value_key or "value": value}
            items.append(item)
    else:
        items = []

    for item in items:
        if not isinstance(item, dict):
            continue
        service = item.get("service")
        if isinstance(service, str) and service:
            indexed[service] = item

    return indexed


def infer_service(finding: dict[str, Any], assets: dict[str, dict[str, Any]]) -> str:
    explicit = finding.get("service")
    if isinstance(explicit, str) and explicit:
        return explicit

    file_path = str(finding.get("file", "")).lstrip("./")

    for service, asset in assets.items():
        repo_path = str(asset.get("repo_path", "")).strip("/").lstrip("./")
        if repo_path and file_path.startswith(repo_path):
            return service

    return "unknown-service"


def add_reason(reasons: list[str], score_delta: int, text: str) -> int:
    sign = "+" if score_delta >= 0 else ""
    reasons.append(f"{sign}{score_delta}: {text}")
    return score_delta


def priority_from_score(score: int) -> str:
    for priority, threshold in PRIORITY_THRESHOLDS:
        if score >= threshold:
            return priority
    return "P4"


def safe_bool(value: Any) -> bool:
    return bool(value) if value is not None else False


def classify_data_weight(classification: str, regulated: bool) -> tuple[int, str]:
    normalized = classification.lower().strip()

    if regulated:
        return 15, "regulated data present"

    if normalized in {"customer_pii", "pii", "phi", "pci", "secrets", "credentials"}:
        return 15, f"sensitive data classification is {classification}"

    if normalized in {"internal", "confidential"}:
        return 8, f"internal/confidential data classification is {classification}"

    if normalized in {"public", "none", "test"}:
        return 0, f"low-sensitivity data classification is {classification}"

    return 3, f"unknown or unspecified data classification is {classification or 'unspecified'}"


def prioritize_finding(
    finding: dict[str, Any],
    assets: dict[str, dict[str, Any]],
    network: dict[str, dict[str, Any]],
    business: dict[str, dict[str, Any]],
    data: dict[str, dict[str, Any]],
    iam: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    reasons: list[str] = []

    severity = str(finding.get("severity", "info")).lower()
    score = SEVERITY_BASE_SCORE.get(severity, 5)
    reasons.append(f"+{score}: base severity is {severity}")

    service = infer_service(finding, assets)

    asset_ctx = assets.get(service, {})
    network_ctx = network.get(service, {})
    business_ctx = business.get(service, {})
    data_ctx = data.get(service, {})
    iam_ctx = iam.get(service, {})

    environment = str(asset_ctx.get("environment", finding.get("environment", "unknown")))
    criticality = str(business_ctx.get("criticality", "unknown"))
    data_classification = str(data_ctx.get("data_classification", "unknown"))
    regulated = safe_bool(data_ctx.get("regulated"))

    if environment in {"prod", "production", "prod-like"}:
        score += add_reason(reasons, 10, f"environment is {environment}")
    elif environment in {"dev", "test", "sandbox"}:
        score += add_reason(reasons, -8, f"environment is {environment}")

    if safe_bool(network_ctx.get("internet_reachable")):
        score += add_reason(reasons, 15, "service is internet reachable")
    else:
        score += add_reason(reasons, -5, "service is not internet reachable")

    if safe_bool(network_ctx.get("production_path")):
        score += add_reason(reasons, 10, "service is in a production path")

    if not safe_bool(network_ctx.get("auth_required")):
        score += add_reason(reasons, 8, "route or service is marked as not requiring auth")

    if safe_bool(network_ctx.get("has_waf")):
        score += add_reason(reasons, -8, "WAF or edge filtering is present")
    else:
        score += add_reason(reasons, 4, "no WAF or edge filtering recorded")

    if criticality in {"tier_0", "tier_1", "critical"}:
        score += add_reason(reasons, 10, f"business criticality is {criticality}")
    elif criticality in {"tier_3", "low"}:
        score += add_reason(reasons, -5, f"business criticality is {criticality}")

    data_delta, data_reason = classify_data_weight(data_classification, regulated)
    score += add_reason(reasons, data_delta, data_reason)

    if safe_bool(iam_ctx.get("over_permissive")):
        score += add_reason(reasons, 8, "service identity is marked over-permissive")

    privilege_level = str(iam_ctx.get("privilege_level", "")).lower()
    if privilege_level in {"admin", "high", "privileged"}:
        score += add_reason(reasons, 5, f"privilege level is {privilege_level}")

    confidence = str(finding.get("confidence", "medium")).lower()
    if confidence == "high":
        score += add_reason(reasons, 5, "scanner confidence is high")
    elif confidence == "low":
        score += add_reason(reasons, -5, "scanner confidence is low")

    validation_status = str(finding.get("validation_status", "pending_validation")).lower()
    if validation_status in {"confirmed", "confirmed_in_lab", "validated"}:
        score += add_reason(reasons, 10, f"validation status is {validation_status}")
    elif validation_status in {"false_positive", "not_reproducible"}:
        score += add_reason(reasons, -60, f"validation status is {validation_status}")
    elif validation_status in {"likely_test_fixture", "test_fixture"}:
        score += add_reason(reasons, -25, f"validation status is {validation_status}")
    else:
        reasons.append(f"+0: validation status is {validation_status}")

    score = max(0, min(100, score))
    priority = priority_from_score(score)

    enriched = {
        **finding,
        "service": service,
        "environment": environment,
        "business_criticality": criticality,
        "data_classification": data_classification,
        "internet_reachable": safe_bool(network_ctx.get("internet_reachable")),
        "production_path": safe_bool(network_ctx.get("production_path")),
        "auth_required": safe_bool(network_ctx.get("auth_required")),
        "has_waf": safe_bool(network_ctx.get("has_waf")),
        "risk_score": score,
        "priority": priority,
        "decision_reasons": reasons,
    }

    return enriched


def markdown_escape(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def generate_risk_register(findings: list[dict[str, Any]]) -> str:
    generated_at = datetime.now(timezone.utc).isoformat()

    lines = [
        "# Prioritized Risk Register",
        "",
        f"Generated: {generated_at}",
        "",
        "| Priority | Score | Finding | Severity | Service | Type | Validation | Summary |",
        "|---|---:|---|---|---|---|---|---|",
    ]

    for finding in findings:
        summary = "; ".join(finding.get("decision_reasons", [])[:4])
        lines.append(
            "| {priority} | {score} | {finding_id} | {severity} | {service} | {type_} | {validation} | {summary} |".format(
                priority=markdown_escape(finding.get("priority", "")),
                score=markdown_escape(finding.get("risk_score", "")),
                finding_id=markdown_escape(finding.get("finding_id", "")),
                severity=markdown_escape(finding.get("severity", "")),
                service=markdown_escape(finding.get("service", "")),
                type_=markdown_escape(finding.get("type", "")),
                validation=markdown_escape(finding.get("validation_status", "pending_validation")),
                summary=markdown_escape(summary),
            )
        )

    lines.extend(
        [
            "",
            "## Notes",
            "",
            "- This report is generated from lab data only.",
            "- Scores are context-aware and evidence-driven, not scanner-only.",
            "- Validation and remediation must remain inside the controlled lab boundary.",
        ]
    )

    return "\n".join(lines) + "\n"


def generate_decision_trace(findings: list[dict[str, Any]]) -> str:
    generated_at = datetime.now(timezone.utc).isoformat()

    lines = [
        "# Decision Trace",
        "",
        f"Generated: {generated_at}",
        "",
        "This file records why each finding received its priority.",
        "",
    ]

    for finding in findings:
        lines.extend(
            [
                f"## {finding.get('finding_id', 'unknown')} - {finding.get('priority', 'P4')}",
                "",
                f"- Service: {finding.get('service', 'unknown')}",
                f"- Severity: {finding.get('severity', 'unknown')}",
                f"- Risk score: {finding.get('risk_score', 0)}",
                f"- Validation: {finding.get('validation_status', 'pending_validation')}",
                "",
                "Decision reasons:",
                "",
            ]
        )

        for reason in finding.get("decision_reasons", []):
            lines.append(f"- {reason}")

        lines.append("")

    return "\n".join(lines)


def main() -> None:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    findings_raw = load_json(EVIDENCE_DIR / "findings.json", [])
    findings = normalize_findings(findings_raw)

    assets = index_services(load_json(CONTEXT_DIR / "assets.json", {"services": []}))
    network = index_services(load_json(CONTEXT_DIR / "network-topology.json", {"services": []}))
    business = index_services(
        load_json(CONTEXT_DIR / "business-criticality.json", {"services": []}),
        value_key="criticality",
    )
    data = index_services(load_json(CONTEXT_DIR / "data-classification.json", {"services": []}))
    iam = index_services(load_json(CONTEXT_DIR / "iam-permissions.json", {"services": []}))

    prioritized = [
        prioritize_finding(finding, assets, network, business, data, iam)
        for finding in findings
    ]

    prioritized.sort(key=lambda item: item.get("risk_score", 0), reverse=True)

    write_json(EVIDENCE_DIR / "prioritized-findings.json", prioritized)
    (EVIDENCE_DIR / "prioritized-risk-register.md").write_text(
        generate_risk_register(prioritized),
        encoding="utf-8",
    )
    (EVIDENCE_DIR / "decision-trace.md").write_text(
        generate_decision_trace(prioritized),
        encoding="utf-8",
    )

    print(f"Prioritized {len(prioritized)} findings.")
    print(f"Wrote {EVIDENCE_DIR / 'prioritized-findings.json'}")
    print(f"Wrote {EVIDENCE_DIR / 'prioritized-risk-register.md'}")
    print(f"Wrote {EVIDENCE_DIR / 'decision-trace.md'}")


if __name__ == "__main__":
    main()
