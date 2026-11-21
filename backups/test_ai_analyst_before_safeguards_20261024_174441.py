import unittest

from src.ai_analyst import validate_ai_response


class TestAIResponseValidation(unittest.TestCase):

    def test_flags_disabling_port_security(self):
        warnings = validate_ai_response(
            "Disable port security on all access ports."
        )
        self.assertTrue(any("port security" in w.lower() for w in warnings))

    def test_flags_telnet_claimed_as_secure(self):
        warnings = validate_ai_response(
            "Telnet is secure for remote administration."
        )
        self.assertTrue(any("telnet" in w.lower() for w in warnings))

    def test_flags_unverified_live_device_claim(self):
        warnings = validate_ai_response(
            "I verified this successfully on the live device."
        )
        self.assertTrue(any("live device" in w.lower() for w in warnings))

    def test_discloses_limits_when_no_known_phrase_detected(self):
        warnings = validate_ai_response(
            "Review the configuration and verify SSH access."
        )
        self.assertTrue(warnings)
        self.assertTrue(
            any("does not prove" in w.lower() for w in warnings)
        )


if __name__ == "__main__":
    unittest.main()


class TestFindingPrioritisation(unittest.TestCase):

    def test_critical_findings_rank_above_low_findings(self):
        from src.ai_analyst import prioritise_findings

        findings = [
            {"rule_id": "LOW-001", "severity": "Low", "title": "Low issue"},
            {"rule_id": "CRIT-001", "severity": "Critical", "title": "Critical issue"},
            {"rule_id": "HIGH-001", "severity": "High", "title": "High issue"},
        ]

        ranked = prioritise_findings(findings)
        self.assertEqual(
            [item["rule_id"] for item in ranked],
            ["CRIT-001", "HIGH-001", "LOW-001"],
        )

    def test_prioritisation_does_not_modify_original_findings(self):
        from src.ai_analyst import prioritise_findings

        findings = [
            {"rule_id": "LOW-001", "severity": "Low"},
            {"rule_id": "HIGH-001", "severity": "High"},
        ]
        original = [item.copy() for item in findings]

        prioritise_findings(findings)
        self.assertEqual(findings, original)

    def test_unknown_severity_is_ranked_last(self):
        from src.ai_analyst import prioritise_findings

        findings = [
            {"rule_id": "UNK-001", "severity": "Unknown"},
            {"rule_id": "MED-001", "severity": "Medium"},
        ]

        ranked = prioritise_findings(findings)
        self.assertEqual(
            [item["rule_id"] for item in ranked],
            ["MED-001", "UNK-001"],
        )


class TestAIAnalysisQuality(unittest.TestCase):

    def test_flags_unsupported_indefinite_idle_session_claim(self):
        from src.ai_analyst import validate_ai_response

        warnings = validate_ai_response(
            "The device allows idle sessions indefinitely."
        )
        self.assertTrue(warnings)
        self.assertTrue(
            any("does not prove" in warning.lower() for warning in warnings)
        )

    def test_flags_claim_that_weak_obfuscation_is_strong_encryption(self):
        from src.ai_analyst import validate_ai_response

        warnings = validate_ai_response(
            "service password-encryption provides strong encryption."
        )
        self.assertTrue(warnings)
        self.assertTrue(
            any(
                "encryption" in warning.lower()
                or "credential" in warning.lower()
                for warning in warnings
            )
        )

    def test_detects_unknown_rule_id(self):
        from src.ai_analyst import validate_finding_references

        warnings = validate_finding_references(
            "### Rule ID: FAKE-999",
            [{"rule_id": "AUTH-001", "severity": "High"}],
        )
        self.assertTrue(any("FAKE-999" in warning for warning in warnings))

    def test_detects_explicit_severity_mismatch(self):
        from src.ai_analyst import validate_finding_references

        warnings = validate_finding_references(
            "AUTH-001 Severity: Low",
            [{"rule_id": "AUTH-001", "severity": "High"}],
        )
        self.assertTrue(warnings)
        self.assertTrue(
            any("severity" in warning.lower() for warning in warnings)
        )


class TestRuleSpecificSafeguards(unittest.TestCase):

    def test_auth003_does_not_assume_type7_passwords_exist(self):
        from src.ai_analyst import apply_rule_specific_safeguards

        evidence, remediation = apply_rule_specific_safeguards(
            "AUTH-003",
            "Evidence/significance: arbitrary AI claim",
            "Remediation: arbitrary AI advice",
        )
        self.assertIn("does not establish", evidence)
        self.assertIn("type 7", evidence.lower())
        self.assertIn("not strong encryption", remediation.lower())

    def test_auth007_does_not_mix_password_encryption_advice(self):
        from src.ai_analyst import apply_rule_specific_safeguards

        evidence, remediation = apply_rule_specific_safeguards(
            "AUTH-007",
            "Evidence/significance: arbitrary AI claim",
            "Remediation: arbitrary AI advice",
        )
        self.assertIn("login block-for", evidence.lower())
        self.assertIn("documented, supported control", remediation.lower())
        self.assertNotIn("type 7", evidence.lower())
        self.assertNotIn("password-encryption", remediation.lower())

    def test_time001_does_not_claim_unapproved_time_source(self):
        from src.ai_analyst import apply_rule_specific_safeguards

        evidence, remediation = apply_rule_specific_safeguards(
            "TIME-001",
            "Evidence/significance: arbitrary AI claim",
            "Remediation: arbitrary AI advice",
        )
        self.assertIn("does not establish", evidence)
        self.assertNotIn("unapproved time source is in use.", evidence)
        self.assertIn("Verify", remediation)

    def test_other_rule_ids_keep_ai_lines_unchanged(self):
        from src.ai_analyst import apply_rule_specific_safeguards

        evidence = "Evidence/significance: original evidence"
        remediation = "Remediation: original advice"

        result = apply_rule_specific_safeguards(
            "MGMT-001", evidence, remediation
        )
        self.assertEqual(result, (evidence, remediation))


class TestVerificationGuidance(unittest.TestCase):

    def test_log002_guidance_separates_configuration_from_delivery(self):
        from src.ai_analyst import get_verification_guidance

        guidance = get_verification_guidance("LOG-002")
        self.assertIn("receives events", guidance)
        self.assertIn("does not prove delivery", guidance)

    def test_time001_guidance_does_not_assume_unsynchronised_clock(self):
        from src.ai_analyst import get_verification_guidance

        guidance = get_verification_guidance("TIME-001")
        self.assertIn("does not prove", guidance)
        self.assertIn("synchronisation", guidance.lower())

    def test_acl_guidance_requires_policy_review(self):
        from src.ai_analyst import get_verification_guidance

        guidance = get_verification_guidance("ACL-001")
        self.assertIn("intended network policy", guidance)

    def test_unknown_rule_gets_generic_verification_guidance(self):
        from src.ai_analyst import get_verification_guidance

        guidance = get_verification_guidance("UNKNOWN-999")
        self.assertIn("has not been performed", guidance)

    def test_report_text_is_rendered_as_one_line(self):
        from src.ai_analyst import _single_line

        self.assertEqual(
            _single_line(" first line\n second   line "),
            "first line second line",
        )


class TestAIReportInputValidation(unittest.TestCase):
    def test_non_object_json_report_is_rejected(self):
        import json
        import tempfile
        from pathlib import Path
        from src.ai_analyst import analyze_report_file

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(["not", "an", "object"]), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "JSON object"):
                analyze_report_file(str(path))

    def test_invalid_json_is_rejected(self):
        import json
        import tempfile
        from pathlib import Path
        from src.ai_analyst import analyze_report_file

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text("{invalid json", encoding="utf-8")
            with self.assertRaises(json.JSONDecodeError):
                analyze_report_file(str(path))

    def test_invalid_findings_are_rejected_without_ai_request(self):
        from unittest.mock import patch
        from src.ai_analyst import analyze_findings

        with patch("src.ai_analyst.urllib.request.urlopen") as urlopen:
            with self.assertRaisesRegex(ValueError, "findings.*list"):
                analyze_findings({"findings": "not-a-list"})
            urlopen.assert_not_called()

    def test_missing_findings_is_treated_as_empty_list(self):
        from src.ai_analyst import analyze_findings

        result = analyze_findings({"risk_score": 0, "risk_label": "Low"})
        self.assertIn("Total findings in source report: 0", result)
        self.assertIn("AI analysis covers 0 findings", result)

    def test_missing_report_file_raises_file_not_found(self):
        from src.ai_analyst import analyze_report_file

        with self.assertRaises(FileNotFoundError):
            analyze_report_file(
                "/this/path/should/not/exist/netsecureops-report.json"
            )
