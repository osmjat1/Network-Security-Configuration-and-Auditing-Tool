
import unittest

from src.auditor import audit_config


class AuditorTests(unittest.TestCase):
    def test_detects_telnet(self):
        config = """
hostname TEST
line vty 0 4
 transport input telnet
!
"""
        result = audit_config(config)
        rule_ids = {item["rule_id"] for item in result["findings"]}
        self.assertIn("MGMT-003", rule_ids)

    def test_detects_vlan_one_access_port(self):
        config = """
hostname TEST
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 1
!
"""
        result = audit_config(config)
        rule_ids = {item["rule_id"] for item in result["findings"]}
        self.assertIn("VLAN-001", rule_ids)

    def test_empty_configuration_returns_report(self):
        result = audit_config("")
        self.assertEqual(result["tool"], "NetSecureOps")
        self.assertIn("findings", result)
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)


if __name__ == "__main__":
    unittest.main()


    def test_rule_tracking_counts_are_consistent(self):
        from src.auditor import audit_config

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
        from src.auditor import audit_config

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
        from src.auditor import audit_config

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
