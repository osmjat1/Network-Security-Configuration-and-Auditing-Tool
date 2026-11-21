"""Project-defined compliance mapping for NetSecureOps.

This module does not certify compliance with any external framework.
A control is PASS only when its rule ID is explicitly supplied as passed.
The current auditor primarily emits failed findings, so missing findings
alone are not enough to establish PASS.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


CONTROL_CATALOG: list[dict[str, Any]] = [
    {
        "control_id": "NSO-AUTH-01",
        "domain": "Authentication",
        "title": "Privileged access secret",
        "description": "An enable secret is configured where local privileged authentication is used.",
        "rule_ids": ["AUTH-001"],
    },
    {
        "control_id": "NSO-AUTH-02",
        "domain": "Authentication",
        "title": "Legacy enable password",
        "description": "Legacy enable password syntax is not present.",
        "rule_ids": ["AUTH-002"],
    },
    {
        "control_id": "NSO-AUTH-03",
        "domain": "Authentication",
        "title": "Password obfuscation setting",
        "description": "The configuration includes service password-encryption; this is weak obfuscation, not strong encryption.",
        "rule_ids": ["AUTH-003"],
    },
    {
        "control_id": "NSO-AUTH-04",
        "domain": "Authentication",
        "title": "Protected local username",
        "description": "A local username using secret syntax is detected.",
        "rule_ids": ["AUTH-004", "AUTH-005"],
    },
    {
        "control_id": "NSO-AUTH-05",
        "domain": "Authentication",
        "title": "AAA configuration",
        "description": "AAA new-model is explicitly configured where appropriate.",
        "rule_ids": ["AUTH-006"],
    },
    {
        "control_id": "NSO-AUTH-06",
        "domain": "Authentication",
        "title": "Login failure throttling",
        "description": "Login failure blocking is configured where supported and appropriate.",
        "rule_ids": ["AUTH-007"],
    },
    {
        "control_id": "NSO-MGMT-01",
        "domain": "Management Plane",
        "title": "SSH version 2",
        "description": "SSH version 2 is explicitly configured.",
        "rule_ids": ["MGMT-001"],
    },
    {
        "control_id": "NSO-MGMT-02",
        "domain": "Management Plane",
        "title": "HTTP management service",
        "description": "Clear-text HTTP management is not enabled unless explicitly required.",
        "rule_ids": ["MGMT-006"],
    },
    {
        "control_id": "NSO-MGMT-03",
        "domain": "Management Plane",
        "title": "VTY management access",
        "description": "VTY sections and their authentication, transport and idle-timeout policies are reviewed.",
        "rule_ids": ["MGMT-002", "MGMT-003", "MGMT-004", "MGMT-005", "MGMT-009"],
    },
    {
        "control_id": "NSO-LOG-01",
        "domain": "Logging and Time",
        "title": "Log timestamps",
        "description": "Log timestamps are explicitly configured.",
        "rule_ids": ["LOG-001"],
    },
    {
        "control_id": "NSO-LOG-02",
        "domain": "Logging and Time",
        "title": "Central syslog destination",
        "description": "A remote syslog destination is configured and separately verified as reachable.",
        "rule_ids": ["LOG-002"],
    },
    {
        "control_id": "NSO-TIME-01",
        "domain": "Logging and Time",
        "title": "Time synchronization",
        "description": "An NTP server is configured and separately verified as reachable.",
        "rule_ids": ["TIME-001"],
    },
    {
        "control_id": "NSO-SVC-01",
        "domain": "Network Services",
        "title": "SNMP community strings",
        "description": "Legacy SNMP community strings are reviewed and, where possible, replaced with SNMPv3.",
        "rule_ids": ["SVC-001", "SVC-002"],
    },
    {
        "control_id": "NSO-NET-01",
        "domain": "Network Security",
        "title": "Source-routing protection",
        "description": "Source routing is explicitly disabled.",
        "rule_ids": ["NET-001", "NET-002"],
    },
    {
        "control_id": "NSO-NET-02",
        "domain": "Network Security",
        "title": "Directed broadcast protection",
        "description": "IP directed broadcasts are not enabled.",
        "rule_ids": ["NET-003"],
    },
    {
        "control_id": "NSO-ACL-01",
        "domain": "Access Control",
        "title": "IPv4 ACL policy",
        "description": "ACL definitions and their placement are reviewed against the approved network design.",
        "rule_ids": ["ACL-001", "ACL-002"],
    },
    {
        "control_id": "NSO-VLAN-01",
        "domain": "Layer 2 Security",
        "title": "Access-port VLAN assignment",
        "description": "Access ports are not explicitly assigned to VLAN 1 where a dedicated VLAN is required.",
        "rule_ids": ["VLAN-001"],
    },
    {
        "control_id": "NSO-VLAN-02",
        "domain": "Layer 2 Security",
        "title": "Trunk VLAN restrictions",
        "description": "Trunks have an explicit allowed-VLAN list that is limited to required VLANs.",
        "rule_ids": ["VLAN-002", "VLAN-003"],
    },
    {
        "control_id": "NSO-VLAN-03",
        "domain": "Layer 2 Security",
        "title": "Trunk negotiation",
        "description": "Trunk negotiation is reviewed and disabled where appropriate and supported.",
        "rule_ids": ["VLAN-004"],
    },
    {
        "control_id": "NSO-PORT-01",
        "domain": "Layer 2 Security",
        "title": "Access-port security",
        "description": "Port security is reviewed for access ports where supported and appropriate.",
        "rule_ids": ["PORT-001"],
    },
    {
        "control_id": "NSO-STP-01",
        "domain": "Layer 2 Security",
        "title": "Edge-port protections",
        "description": "PortFast and BPDU Guard are reviewed for genuine endpoint-facing ports.",
        "rule_ids": ["STP-001", "STP-002"],
    },
]


def _finding_list(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        raise ValueError("Report field 'findings' must be a list.")

    for index, finding in enumerate(findings):
        if not isinstance(finding, dict) or not isinstance(finding.get("rule_id"), str):
            raise ValueError(f"Finding at index {index} must be an object with a string rule_id.")
    return findings


def assess_compliance(
    report: dict[str, Any],
    passed_rule_ids: set[str] | list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Map audit findings to project controls.

    FAIL: one or more mapped findings exist.
    PASS: every mapped rule ID is explicitly provided in passed_rule_ids,
          and no mapped finding exists.
    NOT ASSESSED: otherwise.

    The current auditor does not yet emit authoritative passed_rule_ids.
    Therefore, without explicit pass evidence, controls without findings
    remain NOT ASSESSED rather than being guessed as PASS.
    """
    findings = _finding_list(report)
    passed = set(passed_rule_ids or [])
    findings_by_rule: dict[str, list[dict[str, Any]]] = {}

    for finding in findings:
        findings_by_rule.setdefault(finding["rule_id"], []).append(finding)

    results: list[dict[str, Any]] = []

    for control in CONTROL_CATALOG:
        rule_ids = control["rule_ids"]
        evidence: list[dict[str, Any]] = []

        for rule_id in rule_ids:
            for finding in findings_by_rule.get(rule_id, []):
                evidence.append({
                    "rule_id": rule_id,
                    "title": finding.get("title", rule_id),
                    "severity": finding.get("severity", "Unknown"),
                    "evidence": finding.get("evidence", ""),
                    "recommendation": finding.get("recommendation", ""),
                })

        if evidence:
            status = "FAIL"
        elif all(rule_id in passed for rule_id in rule_ids):
            status = "PASS"
        else:
            status = "NOT ASSESSED"

        results.append({
            "control_id": control["control_id"],
            "domain": control["domain"],
            "title": control["title"],
            "description": control["description"],
            "rule_ids": rule_ids,
            "status": status,
            "evidence": evidence,
        })

    counts = {
        status: sum(item["status"] == status for item in results)
        for status in ("PASS", "FAIL", "NOT ASSESSED")
    }
    total = len(results)
    assessed = counts["PASS"] + counts["FAIL"]

    # Assessment coverage and pass rate are deliberately different metrics.
    assessment_coverage = round(assessed / total * 100, 2) if total else 0.0
    pass_rate = round(counts["PASS"] / assessed * 100, 2) if assessed else None

    return {
        "tool": "NetSecureOps",
        "module": "Project-defined Compliance Mapping",
        "mapping_notice": (
            "This is a project-defined control mapping, not an official compliance "
            "certification or a claim of conformance to an external framework."
        ),
        "source_config": report.get("source_config"),
        "audit_id": report.get("audit_id"),
        "summary": {
            "total_controls": total,
            "pass": counts["PASS"],
            "fail": counts["FAIL"],
            "not_assessed": counts["NOT ASSESSED"],
            "assessment_coverage_percent": assessment_coverage,
            "pass_rate_percent_of_assessed": pass_rate,
        },
        "controls": results,
        "limitations": [
            "The current auditor primarily emits findings and does not provide complete pass evidence.",
            "A missing finding is not treated as proof that a control passed.",
            "Static configuration analysis does not verify live reachability, device state, or operational effectiveness.",
            "Controls may be platform-, topology-, or policy-dependent and require human review.",
        ],
    }


def write_compliance_outputs(
    result: dict[str, Any],
    output_dir: str | Path,
) -> tuple[Path, Path]:
    """Write compliance assessment JSON and CSV files."""
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)

    json_path = destination / "compliance_report.json"
    csv_path = destination / "compliance_controls.csv"

    json_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "control_id", "domain", "title", "status", "rule_ids",
                "description", "evidence", "recommendations",
            ],
        )
        writer.writeheader()
        for control in result.get("controls", []):
            writer.writerow({
                "control_id": control["control_id"],
                "domain": control["domain"],
                "title": control["title"],
                "status": control["status"],
                "rule_ids": "; ".join(control["rule_ids"]),
                "description": control["description"],
                "evidence": " | ".join(
                    f'{item["rule_id"]}: {item["evidence"]}'
                    for item in control["evidence"]
                ),
                "recommendations": " | ".join(
                    item["recommendation"] for item in control["evidence"]
                ),
            })

    return json_path, csv_path
