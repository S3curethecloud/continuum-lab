#!/usr/bin/env python3
"""
Continuum Lab v0.1 - Dependency audit adapter.

This is a local-only dependency scanner adapter for the lab. It reads the demo
requirements file and emits scanner-style JSON for known intentionally outdated
dependency markers.

It does not install packages, call external APIs, query vulnerability services,
or mutate resources.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "apps/vulnerable-python-api/requirements.txt"
OUTPUT = ROOT / "scanners/dependency-audit/dependency-audit-output.json"


def parse_requirements(path: Path) -> list[str]:
    if not path.exists():
        return []

    lines = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def main() -> None:
    generated_at = datetime.now(timezone.utc).isoformat()
    requirements = parse_requirements(TARGET)

    findings = []

    for requirement in requirements:
        normalized = requirement.lower().replace(" ", "")

        if normalized == "django==2.2.0":
            findings.append(
                {
                    "finding_id": "FIND-002",
                    "source": "dependency-audit",
                    "scanner_family": "dependency",
                    "package": "django",
                    "installed_version": "2.2.0",
                    "fixed_version": "2.2.28",
                    "type": "vulnerable_dependency",
                    "service": "admin-worker",
                    "file": str(TARGET.relative_to(ROOT)),
                    "severity": "critical",
                    "confidence": "medium",
                    "validation_status": "unconfirmed",
                    "description": "Outdated Django dependency marker found in local lab requirements file.",
                    "discovery_method": "dependency_audit_adapter",
                    "safe_lab_only": True,
                    "external_targeting": False,
                    "production_targeting": False,
                    "cloud_mutation": False,
                    "advisory": {
                        "id": "CONTINUUM-LAB-DJANGO-2-2-0",
                        "source": "local_lab_fixture",
                        "summary": "Local lab fixture representing an outdated dependency finding."
                    }
                }
            )

    output = {
        "schema": "continuum-lab-dependency-audit-output/v0.1",
        "generated_at": generated_at,
        "scope": {
            "environment": "local_lab_only",
            "external_targeting": False,
            "production_targeting": False,
            "cloud_mutation": False,
            "real_credentials": False
        },
        "target": str(TARGET.relative_to(ROOT)),
        "findings": findings
    }

    OUTPUT.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"Dependency audit findings: {len(findings)}")
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
