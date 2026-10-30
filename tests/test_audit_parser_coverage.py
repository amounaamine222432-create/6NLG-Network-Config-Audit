import json
import unittest

from scripts.audit_parser_coverage import audit_text


class CoverageAuditTests(unittest.TestCase):
    def test_good_interface_not_counted_as_opaque(self):
        report = audit_text("hostname R1\ninterface Loopback0\n ip address 10.0.0.1 255.255.255.255\n",
                            file="sample.cfg")
        self.assertEqual(report["unparsed_global_count"], 0)
        self.assertEqual(report["nested_opaque_count"], 0)

    def test_unsupported_interface_command_is_counted(self):
        report = audit_text("interface GigabitEthernet0/0\n ipv6 address 2001:db8::1/64\n",
                            file="sample.cfg")
        self.assertEqual(report["nested_opaque_by_scope"]["interface"], 1)

    def test_platform_is_distinct_from_unknowns(self):
        report = audit_text("boot-start-marker\nno scheduler allocate\n", file="sample.cfg")
        self.assertEqual(report["unparsed_global_count"], 0)
        self.assertEqual(report["source_only_counts"]["platform_commands"], 2)
        self.assertFalse(report["fully_modeled"])

    def test_xr_warning_raised(self):
        report = audit_text("hostname PE-1\nrouter static\n address-family ipv4 unicast\n",
                            file="PE-1.cfg")
        self.assertTrue(report["ios_xr_or_advanced_syntax_hints"])
        self.assertEqual(report["status"], "review_dialect_before_normalization")

    def test_xr_header_blocks_false_ios_success(self):
        report = audit_text("!! IOS XR Configuration 26.1.1\nhostname PE-1\nrouter static\n",
                            file="PE-1.cfg")
        self.assertEqual(report["source_format"], "ios_xr_header_confirmed")
        self.assertEqual(report["status"], "incompatible_ios_xr_input")

    def test_credentials_not_exposed(self):
        secret = "NE_PAS_EXPORTER_SECRET_12345"
        report = audit_text(f"username admin secret 0 {secret}\nfoo bar {secret}\n", file="R.cfg")
        self.assertNotIn(secret, json.dumps(report))


if __name__ == "__main__":
    unittest.main()
