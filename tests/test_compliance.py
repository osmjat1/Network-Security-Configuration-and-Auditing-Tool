import csv
import json
import tempfile
import unittest
from pathlib import Path

from src.compliance import assess_compliance, write_compliance_outputs


def make_report(findings=None):
    return {
        "source_config": "test-router.txt",
        "audit_id": "test-001",
        "findings": findings or [],
    }


class TestComplianceAssessment(unittest.TestCase):

    def test_missing_findings_are_not_automatically_pass(self):
        result = assess_compliance(make_report())

        self.assertEqual(result["summary"]["pass"], 0)
        self.assertEqual(result["summary"]["fail"], 0)
        self.assertEqual(
            result["summary"]["not_assessed"],
            result["summary"]["total_controls"],
        )
        self.assertEqual(result["summary"]["assessment_coverage_percent"], 0.0)

    def test_mapped_finding_causes_fail(self):
        report = make_report([{
            "rule_id": "AUTH-001",
            "title": "Enable secret not found",
            "severity": "High",
            "evidence": "No enable secret was detected.",
            "recommendation": "Review privileged access.",
        }])

        result = assess_compliance(report)
        control = next(
            item for item in result["controls"]
            if item["control_id"] == "NSO-AUTH-01"
        )

        self.assertEqual(control["status"], "FAIL")
        self.assertEqual(len(control["evidence"]), 1)
        self.assertEqual(result["summary"]["fail"], 1)

    def test_explicit_pass_evidence_can_mark_control_pass(self):
        result = assess_compliance(
            make_report(),
            passed_rule_ids={"AUTH-001"},
        )

        control = next(
            item for item in result["controls"]
            if item["control_id"] == "NSO-AUTH-01"
        )

        self.assertEqual(control["status"], "PASS")
        self.assertEqual(result["summary"]["pass"], 1)
        self.assertGreater(
            result["summary"]["assessment_coverage_percent"], 0
        )

    def test_finding_takes_precedence_over_pass_evidence(self):
        report = make_report([{
            "rule_id": "AUTH-001",
            "title": "Enable secret missing",
            "severity": "High",
            "evidence": "Missing secret.",
            "recommendation": "Review configuration.",
        }])

        result = assess_compliance(
            report,
            passed_rule_ids={"AUTH-001"},
        )

        control = next(
            item for item in result["controls"]
            if item["control_id"] == "NSO-AUTH-01"
        )

        self.assertEqual(control["status"], "FAIL")

    def test_unmapped_findings_do_not_create_false_passes(self):
        report = make_report([{
            "rule_id": "UNKNOWN-999",
            "title": "Unknown check",
            "severity": "Info",
            "evidence": "Unmapped evidence.",
            "recommendation": "Review manually.",
        }])

        result = assess_compliance(report)

        self.assertEqual(result["summary"]["fail"], 0)
        self.assertEqual(result["summary"]["pass"], 0)
        self.assertEqual(result["summary"]["not_assessed"], 21)

    def test_invalid_findings_structure_is_rejected(self):
        with self.assertRaises(ValueError):
            assess_compliance({"findings": "not-a-list"})

        with self.assertRaises(ValueError):
            assess_compliance({"findings": [{"title": "Missing rule ID"}]})

    def test_json_and_csv_exports(self):
        result = assess_compliance(make_report())

        with tempfile.TemporaryDirectory() as temp_dir:
            json_path, csv_path = write_compliance_outputs(
                result, temp_dir
            )

            self.assertTrue(json_path.exists())
            self.assertTrue(csv_path.exists())

            saved_json = json.loads(
                json_path.read_text(encoding="utf-8")
            )
            self.assertEqual(
                saved_json["summary"]["total_controls"], 21
            )

            with csv_path.open(
                newline="", encoding="utf-8"
            ) as handle:
                rows = list(csv.DictReader(handle))

            self.assertEqual(len(rows), 21)
            self.assertIn("status", rows[0])


if __name__ == "__main__":
    unittest.main()
