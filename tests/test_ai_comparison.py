import unittest
from unittest.mock import patch

from src.ai_analyst import generate_ai_audit_comparison


class TestAIAuditComparison(unittest.TestCase):
    def setUp(self):
        self.comparison = {
            "status": "Improved",
            "before_risk_score": 50,
            "after_risk_score": 30,
            "risk_score_delta": -20,
            "resolved_findings_count": 2,
            "new_findings_count": 1,
            "unchanged_findings_count": 3,
            "before_total_findings": 6,
            "after_total_findings": 4,
            "before_severity_counts": {"High": 3, "Medium": 3},
            "after_severity_counts": {"High": 2, "Medium": 2},
            "resolved_findings": [
                {"rule_id": "AUTH-001", "title": "Weak authentication",
                 "severity": "High", "evidence": "Missing enable secret"}
            ],
            "new_findings": [
                {"rule_id": "LOG-002", "title": "Syslog not configured",
                 "severity": "Medium", "evidence": "No logging host"}
            ],
            "unchanged_findings": [
                {"rule_id": "MGMT-003", "title": "Telnet enabled",
                 "severity": "High", "evidence": "transport input telnet"}
            ],
        }

    @patch("src.ai_analyst.generate_json")
    def test_successful_ai_comparison(self, mock_generate):
        mock_generate.return_value = {
            "overall_assessment": "The audit shows improvement.",
            "improvements": "Two findings were resolved.",
            "new_risks": "One new logging finding appeared.",
            "remaining_risks": "Telnet remains enabled.",
            "recommended_actions": ["Disable Telnet after verifying SSH."],
            "confidence": "High",
            "limitations": ["Configuration-only comparison."],
        }

        result = generate_ai_audit_comparison(self.comparison)

        self.assertIn("Deterministic result:** Improved", result)
        self.assertIn("50/100 → 30/100", result)
        self.assertIn("Two findings were resolved.", result)
        self.assertIn("Telnet remains enabled.", result)
        self.assertIn("AI confidence:** High", result)
        mock_generate.assert_called_once()

    @patch("src.ai_analyst.generate_json")
    def test_missing_required_fields_do_not_call_ai(self, mock_generate):
        result = generate_ai_audit_comparison({"status": "Improved"})

        self.assertIn("missing required fields", result)
        mock_generate.assert_not_called()

    @patch("src.ai_analyst.generate_json")
    def test_invalid_confidence_defaults_to_low(self, mock_generate):
        mock_generate.return_value = {
            "overall_assessment": "Assessment available.",
            "improvements": "Some improvement.",
            "new_risks": "One new risk.",
            "remaining_risks": "Some risks remain.",
            "recommended_actions": [],
            "confidence": "Certain",
            "limitations": [],
        }

        result = generate_ai_audit_comparison(self.comparison)

        self.assertIn("AI confidence:** Low", result)

    @patch("src.ai_analyst.generate_json", side_effect=RuntimeError("Model unavailable"))
    def test_ai_failure_returns_safe_message(self, mock_generate):
        result = generate_ai_audit_comparison(self.comparison)

        self.assertIn("AI comparison could not be generated", result)


if __name__ == "__main__":
    unittest.main()
