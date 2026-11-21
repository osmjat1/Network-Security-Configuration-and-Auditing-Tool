"""Evidence-aware verification of before/after security audit reports.

This module never changes router configurations. A finding disappearing
from an after-report is treated as Needs Verification, not automatic proof.
"""

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STATUSES = (
    "Resolved — Verified",
    "Still Present",
    "New Finding",
    "Needs Verification",
)


def load_report(path: Path) -> dict[str, Any]:
    """Load and validate an audit JSON report."""
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read valid JSON report {path}: {exc}") from exc

    if not isinstance(report, dict):
        raise ValueError(f"{path}: report root must be a JSON object")

    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ValueError(f"{path}: findings must be a list")

    for index, item in enumerate(findings):
        if not isinstance(item, dict) or not str(item.get("rule_id", "")).strip():
            raise ValueError(
                f"{path}: finding at index {index} must be an object "
                "with a non-empty rule_id"
            )

    return report


def _score(report: dict[str, Any], label: str) -> int | float | None:
    value = report.get("risk_score")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} risk_score must be numeric")
    if not 0 <= value <= 100:
        raise ValueError(f"{label} risk_score must be between 0 and 100")
    return value


def _identity(finding: dict[str, Any]) -> tuple[str, str, str]:
    """Stable identity, preferring target/interface and then title/evidence."""
    rule = str(finding.get("rule_id", "")).strip()
    target = str(finding.get("target") or finding.get("interface") or "").strip()
    descriptor = str(
        finding.get("title") or finding.get("evidence") or ""
    ).strip()
    return rule, target, descriptor


def _duplicates(findings: list[dict[str, Any]]) -> set[tuple[str, str, str]]:
    counts = Counter(_identity(item) for item in findings)
    return {key for key, count in counts.items() if count > 1}


def _index(findings: list[dict[str, Any]]) -> dict[tuple[str, str, str], dict[str, Any]]:
    result = {}
    for item in findings:
        result.setdefault(_identity(item), item)
    return result


def verify_reports(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    verified_rule_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Compare findings conservatively.

    A disappeared finding is verified only when its rule ID is explicitly
    supplied in verified_rule_ids by the operator after independent checking.
    This flag is an operator attestation, not independently proven device state.
    Duplicate identities and malformed/ambiguous matches require verification.
    """
    for label, report in (("before", before), ("after", after)):
        if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
            raise ValueError(f"{label} report must contain a findings list")
        for index, item in enumerate(report["findings"]):
            if not isinstance(item, dict) or not str(item.get("rule_id", "")).strip():
                raise ValueError(f"{label} finding {index} has no valid rule_id")

    before_score = _score(before, "before")
    after_score = _score(after, "after")
    verified_rule_ids = {
        str(rule).strip() for rule in (verified_rule_ids or set()) if str(rule).strip()
    }

    before_findings = before["findings"]
    after_findings = after["findings"]
    before_dupes = _duplicates(before_findings)
    after_dupes = _duplicates(after_findings)
    before_index = _index(before_findings)
    after_index = _index(after_findings)

    records = []

    for key, old in before_index.items():
        current = after_index.get(key)
        if current is not None:
            records.append({
                "status": "Still Present",
                "rule_id": old.get("rule_id", ""),
                "title": old.get("title", ""),
                "severity": current.get("severity", old.get("severity", "")),
                "target": old.get("target") or old.get("interface", ""),
                "before_evidence": old.get("evidence", ""),
                "after_evidence": current.get("evidence", ""),
                "verification_note": "The matching finding remains in the after-report.",
            })
        else:
            ambiguous = key in before_dupes or key in after_dupes
            explicitly_verified = str(old.get("rule_id", "")).strip() in verified_rule_ids
            if explicitly_verified and not ambiguous:
                status = "Resolved — Verified"
                note = (
                    "Operator marked this rule as independently verified. "
                    "This attestation is not proof of live device state."
                )
            else:
                status = "Needs Verification"
                note = (
                    "Finding is absent from the after-report, but independent "
                    "verification was not recorded."
                )
                if ambiguous:
                    note += " Duplicate identity makes matching ambiguous."

            records.append({
                "status": status,
                "rule_id": old.get("rule_id", ""),
                "title": old.get("title", ""),
                "severity": old.get("severity", ""),
                "target": old.get("target") or old.get("interface", ""),
                "before_evidence": old.get("evidence", ""),
                "after_evidence": "",
                "verification_note": note,
            })

    for key, new in after_index.items():
        if key not in before_index:
            records.append({
                "status": "New Finding",
                "rule_id": new.get("rule_id", ""),
                "title": new.get("title", ""),
                "severity": new.get("severity", ""),
                "target": new.get("target") or new.get("interface", ""),
                "before_evidence": "",
                "after_evidence": new.get("evidence", ""),
                "verification_note": "This finding was not matched in the before-report.",
            })

    counts = Counter(item["status"] for item in records)
    return {
        "tool": "NetSecureOps Remediation Verification Engine",
        "version": "1.0.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "before_source_config": before.get("source_config"),
        "after_source_config": after.get("source_config"),
        "before_audit_time_utc": before.get("audit_time_utc"),
        "after_audit_time_utc": after.get("audit_time_utc"),
        "before_risk_score": before_score,
        "after_risk_score": after_score,
        "risk_score_delta": (
            after_score - before_score
            if before_score is not None and after_score is not None
            else None
        ),
        "before_findings_count": len(before_findings),
        "after_findings_count": len(after_findings),
        "status_counts": {status: counts.get(status, 0) for status in STATUSES},
        "operator_verified_rule_ids": sorted(verified_rule_ids),
        "results": records,
        "limitations": [
            "Static configuration findings do not establish live device state.",
            "A missing finding is not proof of remediation unless independently checked.",
            "Operator verification is an attestation, not independent technical proof.",
            "Finding identity uses rule ID, target/interface, and title or evidence.",
            "Duplicate finding identities are treated as ambiguous.",
            "Risk scores are heuristic and are not proof of security.",
            "This module does not connect to or change network devices.",
        ],
    }


def write_outputs(result: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "verification_report.json"
    csv_path = output_dir / "verification_findings.csv"

    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    columns = [
        "status", "rule_id", "title", "severity", "target",
        "before_evidence", "after_evidence", "verification_note",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(result["results"])

    return json_path, csv_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evidence-aware comparison of before/after NetSecureOps reports."
    )
    parser.add_argument("before", type=Path, help="Before-audit JSON report")
    parser.add_argument("after", type=Path, help="After-audit JSON report")
    parser.add_argument("--out", type=Path, default=Path("reports/verification"))
    parser.add_argument(
        "--verified-rule",
        action="append",
        default=[],
        help=(
            "Rule ID independently checked by the operator. Repeat for each rule. "
            "This records an attestation; it does not verify live device state."
        ),
    )
    args = parser.parse_args()

    try:
        before = load_report(args.before)
        after = load_report(args.after)
        result = verify_reports(
            before, after, verified_rule_ids=set(args.verified_rule)
        )
        json_path, csv_path = write_outputs(result, args.out)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))

    print("NetSecureOps Remediation Verification")
    print(f"Before: {args.before}")
    print(f"After:  {args.after}")
    print(f"Risk score: {result['before_risk_score']} -> {result['after_risk_score']}")
    for status, count in result["status_counts"].items():
        print(f"{status}: {count}")
    print(f"JSON: {json_path}")
    print(f"CSV:  {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
