import json
import tempfile
import unittest
from pathlib import Path

from src.compare_audits import (
    compare_reports,
    finding_key,
    load_report,
    write_outputs,
)


def finding(rule, title, evidence, interface="", severity="Low"):
    return {
        "rule_id": rule,
        "title": title,
        "evidence": evidence,
        "interface": interface,
        "severity": severity,
        "recommendation": "Review and validate.",
    }


def report(findings, score=10):
    return {"risk_score": score, "findings": findings}


class ComparisonTests(unittest.TestCase):
    def test_resolved_new_and_unchanged(self):
        before = report([
            finding("A", "Old issue", "old evidence"),
            finding("B", "Existing issue", "same evidence"),
        ], 20)
        after = report([
            finding("B", "Existing issue", "same evidence"),
            finding("C", "New issue", "new evidence"),
        ], 12)

        result = compare_reports(before, after)

        self.assertEqual(result["resolved_findings_count"], 1)
        self.assertEqual(result["new_findings_count"], 1)
        self.assertEqual(result["unchanged_findings_count"], 1)
        self.assertEqual(result["risk_score_delta"], -8)
        self.assertEqual(result["status"], "Improved")

    def test_same_rule_on_different_interfaces_is_distinct(self):
        before = report([
            finding("PORT-001", "Port security missing", "Missing", "Gi0/1"),
            finding("PORT-001", "Port security missing", "Missing", "Gi0/2"),
        ])
        after = report([
            finding("PORT-001", "Port security missing", "Missing", "Gi0/2"),
        ])

        result = compare_reports(before, after)

        self.assertEqual(result["resolved_findings_count"], 1)
        self.assertEqual(result["unchanged_findings_count"], 1)

    def test_same_rule_without_target_uses_evidence(self):
        before = report([
            finding("AUTH-001", "Secret missing", "Evidence A"),
            finding("AUTH-001", "Secret missing", "Evidence B"),
        ])
        after = report([
            finding("AUTH-001", "Secret missing", "Evidence B"),
        ])

        result = compare_reports(before, after)

        self.assertEqual(result["resolved_findings_count"], 1)
        self.assertEqual(result["unchanged_findings_count"], 1)

    def test_duplicate_identity_is_reported(self):
        item = finding("A", "Same", "Same evidence")
        result = compare_reports(report([item, item]), report([item]))

        self.assertEqual(result["before_duplicate_identity_count"], 1)
        self.assertEqual(result["before_total_findings"], 2)

    def test_invalid_score_is_rejected(self):
        with self.assertRaises(ValueError):
            compare_reports(report([], 101), report([], 10))

    def test_invalid_report_json_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bad.json"
            path.write_text("{broken", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_report(path)

    def test_outputs_are_created(self):
        result = compare_reports(
            report([finding("A", "Issue", "Evidence")], 10),
            report([], 0),
        )
        with tempfile.TemporaryDirectory() as temp:
            write_outputs(result, Path(temp))
            self.assertTrue((Path(temp) / "comparison_report.json").exists())
            self.assertTrue((Path(temp) / "comparison_findings.csv").exists())
            saved = json.loads(
                (Path(temp) / "comparison_report.json").read_text()
            )
            self.assertEqual(saved["resolved_findings_count"], 1)


if __name__ == "__main__":
    unittest.main()
