import unittest
from unittest.mock import patch

from src.ai_analyst import generate_attack_scenarios
from src.ai_engine import AIEngineError


class TestAttackScenarios(unittest.TestCase):

    def setUp(self):
        self.report = {
            "findings": [{
                "rule_id": "MGMT-003",
                "title": "Telnet management enabled",
                "severity": "High",
                "category": "Management",
                "evidence": "Telnet is permitted on VTY lines.",
                "recommendation": "Restrict management to SSH.",
            }]
        }

        self.valid_response = {
            "scenarios": [{
                "title": "Potential interception of management traffic",
                "rule_ids": ["MGMT-003"],
                "attack_path": (
                    "An attacker with network path access could attempt "
                    "to observe an unencrypted management session."
                ),
                "prerequisites": (
                    "The attacker would need network reachability to the "
                    "management interface and an active Telnet session."
                ),
                "potential_impact": (
                    "Management credentials or session information could "
                    "potentially be exposed to an attacker."
                ),
                "detection": (
                    "Review management access logs and monitor unexpected "
                    "connections to Telnet management services."
                ),
                "mitigation": (
                    "Configure and test SSH management before disabling "
                    "Telnet, following administrator approval."
                ),
            }],
            "confidence": "Medium",
            "limitations": (
                "The supplied configuration does not establish network "
                "reachability or prove that an attack has occurred."
            ),
        }

    @patch("src.ai_analyst.generate_json")
    def test_successful_scenario_generation(self, mock_generate):
        mock_generate.return_value = self.valid_response
        result = generate_attack_scenarios(self.report)
        self.assertIn("AI Attack Scenario Analysis", result)
        self.assertIn("MGMT-003", result)
        self.assertIn("Potential impact", result)
        self.assertIn("Assessment limitations", result)

    @patch("src.ai_analyst.generate_json")
    def test_empty_findings_do_not_call_ai(self, mock_generate):
        result = generate_attack_scenarios({"findings": []})
        self.assertIn("No findings", result)
        mock_generate.assert_not_called()

    @patch("src.ai_analyst.generate_json")
    def test_unknown_rule_id_is_rejected(self, mock_generate):
        response = dict(self.valid_response)
        response["scenarios"] = [dict(self.valid_response["scenarios"][0])]
        response["scenarios"][0]["rule_ids"] = ["UNKNOWN-999"]
        mock_generate.return_value = response

        with self.assertRaises(AIEngineError):
            generate_attack_scenarios(self.report)

    @patch("src.ai_analyst.generate_json")
    def test_invalid_confidence_is_rejected(self, mock_generate):
        response = dict(self.valid_response)
        response["confidence"] = "Certain"
        mock_generate.return_value = response

        with self.assertRaises(AIEngineError):
            generate_attack_scenarios(self.report)


if __name__ == "__main__":
    unittest.main()
