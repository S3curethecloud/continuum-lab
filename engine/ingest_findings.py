#!/usr/bin/env python3
"""
Continuum Lab v0.1 - Local discovery ingester.

This script performs safe, local-only discovery against lab files and scanner
outputs, then generates normalized findings.

Current discovery sources:
- Semgrep JSON output when scanners/semgrep/semgrep-output.json exists
- Local static marker fallback for demo continuity
- Local dependency marker
- Local secret fixture marker

It does not exploit targets, scan external systems, call cloud APIs, mutate
resources, or use real credentials.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = ROOT / "evidence"
SEMGREP_OUTPUT = ROOT / "scanners/semgrep/semgrep-output.json"
GITLEAKS_OUTPUT = ROOT / "scanners/gitleaks/gitleaks-output.json"
DEPENDENCY_AUDIT_OUTPUT = ROOT / "scanners/dependency-audit/dependency-audit-output.json"


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


def file_contains(path: Path, needles: list[str]) -> bool:
    if not path.exists():
        return False

    text = path.read_text(encoding="utf-8", errors="replace")
    return all(needle in text for needle in needles)


def stable_finding_id(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8].upper()
    return f"{prefix}-{digest}"


def infer_service_from_path(path: str) -> str:
    if path.startswith("apps/vulnerable-node-api/"):
        return "customer-api"
    if path.startswith("apps/vulnerable-python-api/"):
        return "admin-worker"
    return "unknown-service"


def semgrep_severity_to_continuum(severity: str) -> str:
    normalized = severity.lower()
    if normalized == "error":
        return "high"
    if normalized == "warning":
        return "medium"
    if normalized == "info":
        return "low"
    return "info"


def normalize_semgrep_result(result: dict[str, Any]) -> dict[str, Any]:
    extra = result.get("extra", {}) if isinstance(result.get("extra"), dict) else {}
    metadata = extra.get("metadata", {}) if isinstance(extra.get("metadata"), dict) else {}

    path = str(result.get("path", "unknown"))
    check_id = str(result.get("check_id", "semgrep.unknown"))
    severity = str(extra.get("severity", "INFO"))

    finding_id = str(metadata.get("continuum_finding_id") or "").strip()
    if not finding_id:
        finding_id = stable_finding_id("SEMGREP", f"{check_id}:{path}")

    service = str(metadata.get("continuum_service") or infer_service_from_path(path))
    finding_type = str(metadata.get("continuum_type") or "sast_finding")
    continuum_severity = str(
        metadata.get("continuum_severity") or semgrep_severity_to_continuum(severity)
    )
    confidence = str(metadata.get("continuum_confidence") or "medium")
    scanner_family = str(metadata.get("continuum_scanner_family") or "sast")

    return {
        "finding_id": finding_id,
        "source": "semgrep",
        "scanner_family": scanner_family,
        "type": finding_type,
        "service": service,
        "file": path,
        "severity": continuum_severity,
        "confidence": confidence,
        "validation_status": "pending_validation",
        "description": extra.get("message", "Semgrep finding normalized by Continuum Lab."),
        "discovery_method": "semgrep_json_adapter",
        "check_id": check_id,
        "start": result.get("start", {}),
        "end": result.get("end", {}),
        "external_targeting": False,
        "safe_lab_only": True,
    }


def discover_semgrep_results() -> list[dict[str, Any]]:
    raw = load_json(SEMGREP_OUTPUT, {})
    results = raw.get("results", []) if isinstance(raw, dict) else []

    findings = []
    for result in results:
        if not isinstance(result, dict):
            continue
        findings.append(normalize_semgrep_result(result))

    return findings


def normalize_gitleaks_result(result: dict[str, Any]) -> dict[str, Any]:
    rule_id = str(result.get("RuleID") or result.get("ruleID") or "gitleaks.unknown")
    file_path = str(result.get("File") or result.get("file") or "unknown")

    # The lab intentionally maps the fixture rule to FIND-003 so validation can
    # classify it as likely_test_fixture and cap priority.
    if rule_id == "continuum-lab.fake-api-key-fixture":
        finding_id = "FIND-003"
    else:
        finding_id = stable_finding_id("GITLEAKS", f"{rule_id}:{file_path}")

    return {
        "finding_id": finding_id,
        "source": "gitleaks",
        "scanner_family": "secret",
        "type": "secret_detection",
        "service": infer_service_from_path(file_path),
        "file": file_path,
        "severity": "medium",
        "confidence": "medium",
        "validation_status": "pending_validation",
        "description": result.get("Description", "Gitleaks secret finding normalized by Continuum Lab."),
        "discovery_method": "gitleaks_json_adapter",
        "rule_id": rule_id,
        "start": {
            "line": result.get("StartLine"),
            "column": result.get("StartColumn"),
        },
        "end": {
            "line": result.get("EndLine"),
            "column": result.get("EndColumn"),
        },
        "fingerprint": result.get("Fingerprint", ""),
        "redacted": True,
        "external_targeting": False,
        "safe_lab_only": True,
    }


def discover_gitleaks_results() -> list[dict[str, Any]]:
    raw = load_json(GITLEAKS_OUTPUT, [])

    # Gitleaks JSON reports are commonly a list of finding objects.
    if isinstance(raw, list):
        results = raw
    elif isinstance(raw, dict) and isinstance(raw.get("findings"), list):
        results = raw["findings"]
    else:
        results = []

    findings = []
    for result in results:
        if not isinstance(result, dict):
            continue
        findings.append(normalize_gitleaks_result(result))

    return findings


def normalize_dependency_audit_result(result: dict[str, Any]) -> dict[str, Any]:
    finding_id = str(result.get("finding_id") or "").strip()
    if not finding_id:
        package = str(result.get("package", "unknown"))
        file_path = str(result.get("file", "unknown"))
        finding_id = stable_finding_id("DEP", f"{package}:{file_path}")

    return {
        "finding_id": finding_id,
        "source": "dependency-audit",
        "scanner_family": str(result.get("scanner_family", "dependency")),
        "type": str(result.get("type", "vulnerable_dependency")),
        "service": str(result.get("service", infer_service_from_path(str(result.get("file", ""))))),
        "file": str(result.get("file", "unknown")),
        "severity": str(result.get("severity", "medium")),
        "confidence": str(result.get("confidence", "medium")),
        "validation_status": str(result.get("validation_status", "unconfirmed")),
        "description": str(result.get("description", "Dependency finding normalized by Continuum Lab.")),
        "discovery_method": str(result.get("discovery_method", "dependency_audit_adapter")),
        "package": result.get("package"),
        "installed_version": result.get("installed_version"),
        "fixed_version": result.get("fixed_version"),
        "advisory": result.get("advisory", {}),
        "external_targeting": False,
        "safe_lab_only": True,
    }


def discover_dependency_audit_results() -> list[dict[str, Any]]:
    raw = load_json(DEPENDENCY_AUDIT_OUTPUT, {})

    if isinstance(raw, dict) and isinstance(raw.get("findings"), list):
        results = raw["findings"]
    elif isinstance(raw, list):
        results = raw
    else:
        results = []

    findings = []
    for result in results:
        if not isinstance(result, dict):
            continue
        findings.append(normalize_dependency_audit_result(result))

    return findings


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


def dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}

    for finding in findings:
        finding_id = str(finding.get("finding_id", ""))
        if not finding_id:
            continue

        existing = deduped.get(finding_id)

        # Prefer real scanner output over fallback static marker discovery.
        if existing is None:
            deduped[finding_id] = finding
            continue

        existing_source = str(existing.get("source", ""))
        new_source = str(finding.get("source", ""))

        if existing_source != "semgrep" and new_source == "semgrep":
            deduped[finding_id] = finding

    return [deduped[key] for key in sorted(deduped.keys())]


def main() -> None:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    generated_at = datetime.now(timezone.utc).isoformat()

    findings: list[dict[str, Any]] = []

    semgrep_findings = discover_semgrep_results()
    gitleaks_findings = discover_gitleaks_results()
    dependency_findings = discover_dependency_audit_results()

    findings.extend(semgrep_findings)
    findings.extend(gitleaks_findings)
    findings.extend(dependency_findings)

    # Fallback keeps the lab runnable even before scanner adapters have been run.
    findings.extend(discover_sql_injection_marker())
    findings.extend(discover_dependency_marker())
    findings.extend(discover_secret_fixture_marker())

    findings = dedupe_findings(findings)

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
        "discovery_sources": {
            "semgrep_output_present": SEMGREP_OUTPUT.exists(),
            "semgrep_findings": len(semgrep_findings),
            "gitleaks_output_present": GITLEAKS_OUTPUT.exists(),
            "gitleaks_findings": len(gitleaks_findings),
            "dependency_audit_output_present": DEPENDENCY_AUDIT_OUTPUT.exists(),
            "dependency_audit_findings": len(dependency_findings),
            "static_fallback_enabled": True,
        },
        "findings": findings,
    }

    write_json(EVIDENCE_DIR / "findings.json", output)

    print(f"Discovered {len(findings)} local lab findings.")
    if semgrep_findings:
        print(f"Semgrep adapter findings: {len(semgrep_findings)}")
    else:
        print("Semgrep adapter findings: 0. Static fallback used for SAST demo finding.")

    if gitleaks_findings:
        print(f"Gitleaks adapter findings: {len(gitleaks_findings)}")
    else:
        print("Gitleaks adapter findings: 0. Static fallback used for secret fixture demo finding.")

    if dependency_findings:
        print(f"Dependency adapter findings: {len(dependency_findings)}")
    else:
        print("Dependency adapter findings: 0. Static fallback used for dependency demo finding.")

    print(f"Wrote {EVIDENCE_DIR / 'findings.json'}")


if __name__ == "__main__":
    main()
