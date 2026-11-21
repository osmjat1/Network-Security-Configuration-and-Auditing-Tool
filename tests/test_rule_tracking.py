import unittest
from src.auditor import audit_config


class TestRuleTracking(unittest.TestCase):

    def test_rule_tracking_counts_are_consistent(self):
        report = audit_config(
            "hostname TEST\n"
            "line vty 0 4\n"
            " login local\n"
        )
        self.assertEqual(
            report["checks_run"],
            report["checks_passed"]
            + report["checks_failed"]
            + report["checks_not_assessed"],
        )

    def test_missing_vty_transport_is_not_assessed(self):
        report = audit_config(
            "hostname TEST\n"
            "line vty 0 4\n"
            " login local\n"
        )
        matches = [
            item for item in report["rule_results"]
            if item["rule_id"] == "MGMT-003"
        ]
        self.assertTrue(matches)
        self.assertEqual(matches[0]["status"], "NOT ASSESSED")

    def test_explicit_telnet_transport_fails(self):
        report = audit_config(
            "hostname TEST\n"
            "line vty 0 4\n"
            " transport input telnet\n"
        )
        matches = [
            item for item in report["rule_results"]
            if item["rule_id"] == "MGMT-003"
        ]
        self.assertTrue(matches)
        self.assertEqual(matches[0]["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
