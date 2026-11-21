#!/usr/bin/env python3
"""Compare NetSecureOps audit reports using stable finding identities."""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")


def load_report(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"Cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc

    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise ValueError(f"{path} is not a report with a findings list.")

    for index, finding in enumerate(data["findings"]):
        if not isinstance(finding, dict) or not finding.get("rule_id"):
            raise ValueError(f"{path}: finding {index} has no valid rule_id.")
    return data


def finding_key(item: dict) -> tuple[str, str, str]:
    """Identify a finding by rule, target, and fallback evidence/title."""
    rule_id = str(item.get("rule_id", "")).strip()
    target = str(item.get("target") or item.get("interface") or "").strip()

    # Evidence distinguishes multiple occurrences of the same rule on one target.
    # When no target is available, evidence/title prevents unrelated findings
    # with the same rule ID from collapsing into one dictionary entry.
    detail = str(item.get("evidence") or item.get("title") or "").strip()
    return rule_id, target, detail


def severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = Counter(str(f.get("severity", "Unknown")) for f in findings)
    result = {level: counts.get(level, 0) for level in SEVERITIES}
    for level, count in counts.items():
        if level not in result:
            result[level] = count
    return result


def validate_score(report: dict, label: str) -> int:
    value = report.get("risk_score", 0)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} risk_score must be a number from 0 to 100.")
    if not 0 <= value <= 100 or int(value) != value:
        raise ValueError(f"{label} risk_score must be an integer from 0 to 100.")
    return int(value)


def compare_reports(before: dict, after: dict) -> dict:
    before_findings = before["findings"]
    after_findings = after["findings"]

    before_map = {finding_key(f): f for f in before_findings}
    after_map = {finding_key(f): f for f in after_findings}

    # Warn about duplicate identities: dictionary matching cannot safely
    # distinguish two records with exactly the same identity.
    before_duplicates = len(before_findings) - len(before_map)
    after_duplicates = len(after_findings) - len(after_map)

    resolved = [before_map[k] for k in before_map.keys() - after_map.keys()]
    new = [after_map[k] for k in after_map.keys() - before_map.keys()]
    unchanged = [after_map[k] for k in before_map.keys() & after_map.keys()]

    before_score = validate_score(before, "Before")
    after_score = validate_score(after, "After")
    delta = after_score - before_score

    if delta < 0:
        status = "Improved"
    elif delta > 0:
        status = "Worsened"
    else:
        status = "Unchanged"

    return {
        "tool": "NetSecureOps",
        "comparison_version": "1.1.0",
        "comparison_time_utc": datetime.now(timezone.utc).isoformat(),
        "before_report": before.get("source_config") or before.get("config") or "before report",
        "after_report": after.get("source_config") or after.get("config") or "after report",
        "status": status,
        "before_risk_score": before_score,
        "after_risk_score": after_score,
        "risk_score_delta": delta,
        "resolved_findings_count": len(resolved),
        "new_findings_count": len(new),
        "unchanged_findings_count": len(unchanged),
        "before_total_findings": len(before_findings),
        "after_total_findings": len(after_findings),
        "before_duplicate_identity_count": before_duplicates,
        "after_duplicate_identity_count": after_duplicates,
        "before_severity_counts": severity_counts(before_findings),
        "after_severity_counts": severity_counts(after_findings),
        "resolved_findings": sorted(resolved, key=finding_key),
        "new_findings": sorted(new, key=finding_key),
        "unchanged_findings": sorted(unchanged, key=finding_key),
        "limitations": [
            "Matching uses rule_id, target/interface, and evidence/title.",
            "Exact duplicate finding identities are reported but cannot be uniquely matched.",
            "A lower heuristic risk score does not prove the network is secure.",
            "Static command detection does not prove services are reachable or operational.",
            "Validate configuration and connectivity in an authorized isolated lab."
        ],
    }


def write_outputs(result: dict, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "comparison_report.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8"
    )

    columns = [
        "status", "rule_id", "title", "severity", "target",
        "evidence", "recommendation"
    ]
    with (out_dir / "comparison_findings.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()

        for key, label in (
            ("resolved_findings", "Resolved"),
            ("new_findings", "New"),
            ("unchanged_findings", "Unchanged"),
        ):
            for item in result[key]:
                writer.writerow({
                    "status": label,
                    "rule_id": item.get("rule_id", ""),
                    "title": item.get("title", ""),
                    "severity": item.get("severity", ""),
                    "target": item.get("target") or item.get("interface", ""),
                    "evidence": item.get("evidence", ""),
                    "recommendation": item.get("recommendation", ""),
                })


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare two NetSecureOps JSON audit reports."
    )
    parser.add_argument("before", help="Earlier audit_report.json")
    parser.add_argument("after", help="Later audit_report.json")
    parser.add_argument(
        "--out", default="reports/comparison", help="Output directory"
    )
    args = parser.parse_args()

    try:
        result = compare_reports(
            load_report(Path(args.before)),
            load_report(Path(args.after)),
        )
        write_outputs(result, Path(args.out))
    except (ValueError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print("\n=== NetSecureOps Audit Comparison v1.1.0 ===")
    print(f"Status             : {result['status']}")
    print(f"Before risk score  : {result['before_risk_score']}/100")
    print(f"After risk score   : {result['after_risk_score']}/100")
    print(f"Score change       : {result['risk_score_delta']:+d}")
    print(f"Resolved findings  : {result['resolved_findings_count']}")
    print(f"New findings       : {result['new_findings_count']}")
    print(f"Unchanged findings : {result['unchanged_findings_count']}")
    print(
        "Duplicate identities (before/after): "
        f"{result['before_duplicate_identity_count']}/"
        f"{result['after_duplicate_identity_count']}"
    )
    print(f"JSON report        : {Path(args.out) / 'comparison_report.json'}")
    print(f"CSV report         : {Path(args.out) / 'comparison_findings.csv'}")
    print("\nNote: heuristic score and static findings require independent validation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
