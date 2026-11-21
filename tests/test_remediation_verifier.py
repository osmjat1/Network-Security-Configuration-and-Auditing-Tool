import json
import tempfile
import unittest
from pathlib import Path

from src.remediation_verifier import (
    load_report,
    verify_reports,
    write_outputs,
)


def finding(rule, title, evidence="evidence", severity="High", interface=""):
    return {
        "rule_id": rule,
        "title": title,
        "evidence": evidence,
        "severity": severity,
        "interface": interface,
    }


def report(findings, score=20):
    return {
        "risk_score": score,
        "source_config": "test-config.txt",
        "audit_time_utc": "2026-10-24T10:00:00+00:00",
        "findings": findings,
    }


class RemediationVerifierTests(unittest.TestCase):
    def test_disappeared_finding_needs_verification_by_default(self):
        result = verify_reports(
            report([finding("AUTH-001", "Secret missing")]),
            report([], 10),
        )
        self.assertEqual(result["results"][0]["status"], "Needs Verification")

    def test_operator_attestation_marks_unique_disappeared_rule(self):
        result = verify_reports(
            report([finding("AUTH-001", "Secret missing")]),
            report([], 10),
            verified_rule_ids={"AUTH-001"},
        )
        self.assertEqual(result["results"][0]["status"], "Resolved — Verified")
        self.assertIn("attestation", result["results"][0]["verification_note"])

    def test_matching_finding_is_still_present(self):
        item = finding("AUTH-001", "Secret missing")
        result = verify_reports(report([item]), report([item], 20))
        self.assertEqual(result["results"][0]["status"], "Still Present")

    def test_new_finding_is_detected(self):
        result = verify_reports(
            report([]),
            report([finding("LOG-002", "Syslog missing")], 25),
        )
        self.assertEqual(result["results"][0]["status"], "New Finding")

    def test_duplicate_disappeared_identity_cannot_be_verified(self):
        item = finding("AUTH-001", "Secret missing")
        result = verify_reports(
            report([item, item]),
            report([], 10),
            verified_rule_ids={"AUTH-001"},
        )
        self.assertEqual(result["results"][0]["status"], "Needs Verification")
        self.assertIn("Duplicate", result["results"][0]["verification_note"])

    def test_invalid_score_is_rejected(self):
        with self.assertRaises(ValueError):
            verify_reports(report([], 101), report([], 10))

    def test_invalid_findings_structure_is_rejected(self):
        with self.assertRaises(ValueError):
            verify_reports({"findings": "bad"}, report([]))

    def test_load_report_rejects_invalid_json(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bad.json"
            path.write_text("{bad", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_report(path)

    def test_json_and_csv_outputs_are_created(self):
        result = verify_reports(
            report([finding("AUTH-001", "Secret missing")]),
            report([], 10),
        )
        with tempfile.TemporaryDirectory() as temp:
            json_path, csv_path = write_outputs(result, Path(temp))
            self.assertTrue(json_path.is_file())
            self.assertTrue(csv_path.is_file())
            saved = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(saved["status_counts"]["Needs Verification"], 1)


if __name__ == "__main__":
    unittest.main()
