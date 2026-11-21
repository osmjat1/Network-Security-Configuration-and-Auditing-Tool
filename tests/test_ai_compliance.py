import unittest
from unittest.mock import patch

from src.ai_analyst import generate_ai_compliance_explanation


class TestAIComplianceExplanation(unittest.TestCase):
    def setUp(self):
        self.compliance = {
            "summary": {
                "total_controls": 3,
                "pass": 1,
                "fail": 1,
                "not_assessed": 1,
                "assessment_coverage_percent": 66.7,
                "pass_rate_percent_of_assessed": 50.0,
            },
            "controls": [
                {
                    "control_id": "AUTH-C01",
                    "domain": "Authentication",
                    "title": "Secure authentication",
                    "description": "Authentication controls",
                    "rule_ids": ["AUTH-001"],
                    "status": "FAIL",
                    "evidence": [
                        {
                            "rule_id": "AUTH-001",
                            "severity": "High",
                            "evidence": "Missing enable secret",
                            "recommendation": "Configure a strong enable secret",
                        }
                    ],
                },
                {
                    "control_id": "MGMT-C01",
                    "domain": "Management",
                    "title": "Secure remote access",
                    "description": "Remote management security",
                    "rule_ids": ["MGMT-003"],
                    "status": "PASS",
                    "evidence": [],
                },
                {
                    "control_id": "LOG-C01",
                    "domain": "Logging",
                    "title": "Centralised logging",
                    "description": "Logging configuration",
                    "rule_ids": ["LOG-002"],
                    "status": "NOT ASSESSED",
                    "evidence": [],
                },
            ],
            "limitations": ["Configuration-only assessment."],
        }

    @patch("src.ai_analyst.generate_json")
    def test_successful_compliance_explanation(self, mock_generate):
        mock_generate.return_value = {
            "overall_assessment": "Some controls require attention.",
            "control_explanations": [
                {
                    "control_id": "AUTH-C01",
                    "status": "FAIL",
                    "explanation": "The enable secret is missing.",
                },
                {
                    "control_id": "MGMT-C01",
                    "status": "PASS",
                    "explanation": "The supplied project rules passed.",
                },
                {
                    "control_id": "LOG-C01",
                    "status": "NOT ASSESSED",
                    "explanation": "Further evidence is required.",
                },
            ],
            "priority_gaps": ["Review authentication configuration."],
            "recommended_actions": ["Configure a strong enable secret."],
            "confidence": "High",
            "limitations": ["Configuration-only evidence."],
        }

        result = generate_ai_compliance_explanation(self.compliance)

        self.assertIn("AI Compliance Explanation", result)
        self.assertIn("AUTH-C01 — FAIL", result)
        self.assertIn("MGMT-C01 — PASS", result)
        self.assertIn("LOG-C01 — NOT ASSESSED", result)
        self.assertIn("Some controls require attention.", result)
        self.assertIn("AI confidence:** High", result)
        mock_generate.assert_called_once()

    @patch("src.ai_analyst.generate_json")
    def test_ai_cannot_change_authoritative_statuses(self, mock_generate):
        mock_generate.return_value = {
            "overall_assessment": "Assessment available.",
            "control_explanations": [
                {
                    "control_id": "AUTH-C01",
                    "status": "PASS",
                    "explanation": "Incorrect status supplied by AI.",
                },
                {
                    "control_id": "LOG-C01",
                    "status": "FAIL",
                    "explanation": "Incorrect status supplied by AI.",
                },
            ],
            "priority_gaps": [],
            "recommended_actions": [],
            "confidence": "Medium",
            "limitations": [],
        }

        result = generate_ai_compliance_explanation(self.compliance)

        self.assertNotIn("Incorrect status supplied by AI.", result)
        self.assertIn("No validated individual control explanations", result)

    @patch("src.ai_analyst.generate_json")
    def test_invalid_structure_does_not_call_ai(self, mock_generate):
        result = generate_ai_compliance_explanation({"summary": {}})

        self.assertIn("report structure is invalid", result)
        mock_generate.assert_not_called()

    @patch("src.ai_analyst.generate_json")
    def test_invalid_confidence_defaults_to_low(self, mock_generate):
        mock_generate.return_value = {
            "overall_assessment": "Assessment available.",
            "control_explanations": [],
            "priority_gaps": [],
            "recommended_actions": [],
            "confidence": "Certain",
            "limitations": [],
        }

        result = generate_ai_compliance_explanation(self.compliance)

        self.assertIn("AI confidence:** Low", result)

    @patch(
        "src.ai_analyst.generate_json",
        side_effect=RuntimeError("Model unavailable"),
    )
    def test_ai_failure_returns_safe_message(self, mock_generate):
        result = generate_ai_compliance_explanation(self.compliance)

        self.assertIn("AI compliance explanation could not be generated", result)

    @patch("src.ai_analyst.generate_json")
    def test_empty_controls_do_not_call_ai(self, mock_generate):
        compliance = {
            "summary": {},
            "controls": [],
        }

        result = generate_ai_compliance_explanation(compliance)

        self.assertIn("no valid controls", result)
        mock_generate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
