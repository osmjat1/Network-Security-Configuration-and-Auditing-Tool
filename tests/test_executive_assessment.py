import unittest
from unittest.mock import patch

from src.ai_analyst import generate_executive_assessment
from src.ai_engine import AIEngineError


class TestExecutiveAssessment(unittest.TestCase):

    def setUp(self):
        self.report = {
            "risk_score": 75,
            "risk_label": "High",
            "findings": [
                {
                    "rule_id": "AUTH-001",
                    "title": "Weak authentication",
                    "severity": "High",
                    "category": "Authentication",
                    "evidence": "No password encryption configured.",
                    "recommendation": "Configure secure authentication.",
                }
            ],
        }

        self.valid_response = {
            "overall_posture": "The configuration has significant security weaknesses.",
            "business_impact": "Unauthorised access could affect business operations.",
            "top_risks": [
                {
                    "rule_id": "AUTH-001",
                    "impact": "Weak authentication may increase unauthorised access risk.",
                    "priority": "High",
                }
            ],
            "management_actions": [
                "Review authentication configuration."
            ],
            "confidence": "High",
            "limitations": "Assessment is based only on supplied configuration evidence.",
        }

    @patch("src.ai_analyst.generate_json")
    def test_successful_executive_assessment(self, mock_generate):
        mock_generate.return_value = self.valid_response

        result = generate_executive_assessment(self.report)

        self.assertIn("AI Executive Risk Assessment", result)
        self.assertIn("75/100", result)
        self.assertIn("High", result)
        self.assertIn("AUTH-001", result)
        self.assertIn("Management Actions", result)

    @patch("src.ai_analyst.generate_json")
    def test_unknown_rule_id_is_rejected(self, mock_generate):
        response = dict(self.valid_response)
        response["top_risks"] = [
            {
                "rule_id": "UNKNOWN-999",
                "impact": "Unknown risk.",
                "priority": "High",
            }
        ]
        mock_generate.return_value = response

        with self.assertRaises(AIEngineError):
            generate_executive_assessment(self.report)

    @patch("src.ai_analyst.generate_json")
    def test_invalid_confidence_is_rejected(self, mock_generate):
        response = dict(self.valid_response)
        response["confidence"] = "Certain"
        mock_generate.return_value = response

        with self.assertRaises(AIEngineError):
            generate_executive_assessment(self.report)

    @patch("src.ai_analyst.generate_json")
    def test_invalid_response_structure_is_rejected(self, mock_generate):
        response = dict(self.valid_response)
        del response["limitations"]
        mock_generate.return_value = response

        with self.assertRaises(AIEngineError):
            generate_executive_assessment(self.report)

    @patch("src.ai_analyst.generate_json")
    def test_empty_findings_do_not_call_ai(self, mock_generate):
        report = {
            "risk_score": 0,
            "risk_label": "Low",
            "findings": [],
        }

        result = generate_executive_assessment(report)

        self.assertIn("No findings", result)
        mock_generate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
