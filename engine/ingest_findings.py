#!/usr/bin/env python3
"""
Continuum Lab v0.1 - Local discovery ingester.

This script performs safe, local-only static discovery against lab files and
generates normalized findings.

It does not exploit targets, scan external systems, call cloud APIs, mutate
resources, or use real credentials.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = ROOT / "evidence"


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def file_contains(path: Path, needles: list[str]) -> bool:
    if not path.exists():
        return False

    text = path.read_text(encoding="utf-8", errors="replace")
    return all(needle in text for needle in needles)


def discover_sql_injection_marker() -> list[dict[str, Any]]:
    path = ROOT / "apps/vulnerable-node-api/src/routes/search.js"

    markers = [
        "SELECT id, name, email, tier FROM customers",
        "+ searchTerm +",
        "intentionally vulnerable lab route",
    ]

    if not file_contains(path, markers):
        return []

    return [
        {
            "finding_id": "FIND-001",
            "source": "local-static-discovery",
            "scanner_family": "sast",
            "type": "sql_injection",
            "service": "customer-api",
            "file": str(path.relative_to(ROOT)),
            "severity": "high",
            "confidence": "high",
            "validation_status": "pending_validation",
            "description": "Unsafe SQL-style query construction marker found in local lab route.",
            "discovery_method": "static_marker_match",
            "external_targeting": False,
            "safe_lab_only": True,
        }
    ]


def discover_dependency_marker() -> list[dict[str, Any]]:
    path = ROOT / "apps/vulnerable-python-api/requirements.txt"

    markers = [
        "django==2.2.0",
        "Intentionally outdated dependency marker",
    ]

    if not file_contains(path, markers):
        return []

    return [
        {
            "finding_id": "FIND-002",
            "source": "local-static-discovery",
            "scanner_family": "dependency",
            "type": "vulnerable_dependency",
            "service": "admin-worker",
            "file": str(path.relative_to(ROOT)),
            "severity": "critical",
            "confidence": "medium",
            "validation_status": "unconfirmed",
            "description": "Outdated dependency marker found in local lab requirements file.",
            "discovery_method": "static_dependency_marker_match",
            "external_targeting": False,
            "safe_lab_only": True,
        }
    ]


def discover_secret_fixture_marker() -> list[dict[str, Any]]:
    path = ROOT / "apps/vulnerable-node-api/test/fixtures/example.env"

    markers = [
        "LAB_FAKE_API_KEY",
        "not-a-real-secret-used-for-local-testing-only",
    ]

    if not file_contains(path, markers):
        return []

    return [
        {
            "finding_id": "FIND-003",
            "source": "local-static-discovery",
            "scanner_family": "secret",
            "type": "secret_detection",
            "service": "customer-api",
            "file": str(path.relative_to(ROOT)),
            "severity": "medium",
            "confidence": "low",
            "validation_status": "likely_test_fixture",
            "description": "Secret-like string found in a local test fixture.",
            "discovery_method": "static_secret_fixture_marker_match",
            "external_targeting": False,
            "safe_lab_only": True,
        }
    ]


def main() -> None:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    generated_at = datetime.now(timezone.utc).isoformat()

    findings: list[dict[str, Any]] = []
    findings.extend(discover_sql_injection_marker())
    findings.extend(discover_dependency_marker())
    findings.extend(discover_secret_fixture_marker())

    findings.sort(key=lambda item: item["finding_id"])

    output = {
        "schema": "continuum-lab-normalized-findings/v0.1",
        "generated_at": generated_at,
        "scope": {
            "environment": "local_lab_only",
            "external_targeting": False,
            "cloud_mutation": False,
            "production_targeting": False,
            "real_credentials": False,
        },
        "findings": findings,
    }

    write_json(EVIDENCE_DIR / "findings.json", output)

    print(f"Discovered {len(findings)} local lab findings.")
    print(f"Wrote {EVIDENCE_DIR / 'findings.json'}")


if __name__ == "__main__":
    main()
