#!/usr/bin/env python3
"""
Continuum Lab v0.1 - Safe validation emulator.

This script does not exploit targets, scan external systems, or mutate anything.
It applies lab-only validation rules to normalized findings and records evidence.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONTEXT_DIR = ROOT / "context"
EVIDENCE_DIR = ROOT / "evidence"


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


def normalize_rules(raw: Any) -> dict[str, dict[str, Any]]:
    rules = raw.get("rules", []) if isinstance(raw, dict) else []
    indexed = {}

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        finding_id = rule.get("finding_id")
        if isinstance(finding_id, str) and finding_id:
            indexed[finding_id] = rule

    return indexed


def default_validation(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "finding_id": finding.get("finding_id", "unknown"),
        "validation_status": finding.get("validation_status", "pending_validation"),
        "method": "no_matching_validation_rule",
        "evidence": [
            "No explicit lab validation rule matched this finding",
            "Finding remains pending validation"
        ],
        "safe_validation_only": True,
        "external_targeting": False
    }


def main() -> None:
    findings = normalize_findings(load_json(EVIDENCE_DIR / "findings.json", []))
    rules = normalize_rules(load_json(CONTEXT_DIR / "validation-rules.json", {"rules": []}))

    generated_at = datetime.now(timezone.utc).isoformat()
    results = []

    for finding in findings:
        finding_id = finding.get("finding_id", "unknown")
        rule = rules.get(finding_id, default_validation(finding))

        result = {
            "finding_id": finding_id,
            "source": finding.get("source", "unknown"),
            "type": finding.get("type", "unknown"),
            "service": finding.get("service", "unknown-service"),
            "file": finding.get("file", "unknown"),
            "validation_status": rule.get("validation_status", "pending_validation"),
            "method": rule.get("method", "unspecified"),
            "evidence": rule.get("evidence", []),
            "safe_validation_only": bool(rule.get("safe_validation_only", True)),
            "external_targeting": bool(rule.get("external_targeting", False)),
            "validated_at": generated_at
        }

        if result["external_targeting"]:
            raise SystemExit(
                f"Unsafe validation rule for {finding_id}: external_targeting must be false"
            )

        results.append(result)

    output = {
        "schema": "continuum-lab-validation-results/v0.1",
        "generated_at": generated_at,
        "scope": {
            "environment": "local_lab_only",
            "safe_validation_only": True,
            "external_targeting": False,
            "production_targeting": False,
            "cloud_mutation": False
        },
        "results": results
    }

    write_json(EVIDENCE_DIR / "validation-results.json", output)

    print(f"Validated {len(results)} findings using lab-only rules.")
    print(f"Wrote {EVIDENCE_DIR / 'validation-results.json'}")


if __name__ == "__main__":
    main()
