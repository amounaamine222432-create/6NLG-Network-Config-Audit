import json
from pathlib import Path
import unittest

from audit_engine.cis15_engine import audit_cis_ios15


CATALOGUE_PATH = (
    Path(__file__).resolve().parents[1] /
    "benchmarks/rules/cisco_ios/cis_ios15_v4.1.1_lab.json"
)


class TestCis15Engine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalogue = json.loads(CATALOGUE_PATH.read_text(encoding="utf-8"))

    def setUp(self):
        self.ir = {
            "source": {"vendor": "cisco_ios", "file": "sample.cfg", "sha256": "example"},
            "device": {"hostname": "R-TEST", "platform": {"version": "15.9"}},
            "management": {
                "terminal_lines": [{"line_id": "vty 0 4", "transport_input": ["ssh"],
                                    "source": {"line": 42}}],
                "banners": [{"kind": "exec", "source": {"line": 7}}],
                "enable_secret_configured": True,
            },
            "services": {
                "syslog": {"source_interface": "Loopback0"},
                "ntp": {"authentication_enabled": True},
                "ip_stack": {"source_route_enabled": False},
            },
        }

    def test_all_six_controls_pass_with_l2(self):
        result = audit_cis_ios15(self.ir, self.catalogue, profile="L2")
        self.assertEqual(result["counts"]["PASS"], 6)
        self.assertEqual(result["counts"]["FAIL"], 0)
        self.assertFalse(result["benchmark_conformance_certified"])
        self.assertEqual(result["findings"][0]["evidence"]["vty_lines"][0]["source_line"], 42)

    def test_l1_skips_l2_ntp_rule(self):
        result = audit_cis_ios15(self.ir, self.catalogue, profile="L1")
        self.assertEqual(result["counts"]["PASS"], 5)
        self.assertEqual(result["counts"]["NOT_SELECTED"], 1)

    def test_telnet_with_ssh_fails(self):
        self.ir["management"]["terminal_lines"][0]["transport_input"] = ["ssh", "telnet"]
        result = audit_cis_ios15(self.ir, self.catalogue, profile="L1")
        finding = next(f for f in result["findings"] if f["cis_control_id"] == "1.2.2")
        self.assertEqual(finding["status"], "FAIL")
        self.assertIn("transport input ssh", finding["remediation"])

    def test_missing_banner_is_unknown_by_default(self):
        self.ir["management"]["banners"] = []
        result = audit_cis_ios15(self.ir, self.catalogue)
        finding = next(f for f in result["findings"] if f["cis_control_id"] == "1.3.1")
        self.assertEqual(finding["status"], "UNKNOWN")

    def test_missing_banner_fails_only_when_assumed_complete(self):
        self.ir["management"]["banners"] = []
        result = audit_cis_ios15(self.ir, self.catalogue, complete_config=True)
        finding = next(f for f in result["findings"] if f["cis_control_id"] == "1.3.1")
        self.assertEqual(finding["status"], "FAIL")

    def test_does_not_assume_null_is_compliant(self):
        self.ir["services"]["ip_stack"]["source_route_enabled"] = None
        result = audit_cis_ios15(self.ir, self.catalogue)
        finding = next(f for f in result["findings"] if f["cis_control_id"] == "3.1.1")
        self.assertEqual(finding["status"], "UNKNOWN")

    def test_unsupported_software_major_not_applicable(self):
        self.ir["device"]["platform"]["version"] = "16.12"
        result = audit_cis_ios15(self.ir, self.catalogue, profile="L2")
        self.assertEqual(result["counts"]["NOT_APPLICABLE"], 6)

    def test_missing_software_version_unknown(self):
        self.ir["device"]["platform"]["version"] = None
        result = audit_cis_ios15(self.ir, self.catalogue, profile="L2")
        self.assertEqual(result["counts"]["UNKNOWN"], 6)

    def test_disallow_arbitrary_checks(self):
        altered = json.loads(json.dumps(self.catalogue))
        altered["rules"][0]["check"] = "read_local_accounts_password"
        with self.assertRaises(ValueError):
            audit_cis_ios15(self.ir, altered)


if __name__ == "__main__":
    unittest.main()
