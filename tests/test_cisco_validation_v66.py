"""V6.6: MMI evidence, IOS/XR dialect hints, and held-out indentation case."""

import unittest

from cisco_parser import parse_cisco_ios
from normalizers.cisco_normalizer import normalize_cisco_ios
from scripts.audit_parser_coverage import audit_text


class IOSValidationV66(unittest.TestCase):
    def test_mmi_documented_seconds_and_limits(self):
        data = parse_cisco_ios("mmi polling-interval 60\nmmi snmp-timeout 180\n")
        entries = [x["structured"] for x in data["platform_commands"]]
        self.assertEqual([x["unit"] for x in entries], ["seconds", "seconds"])
        self.assertTrue(all(x["documentation_reference"] == "Cisco OL-2479-02" for x in entries))
        self.assertTrue(all(x["operational_state"] is None for x in entries))

    def test_mmi_invalid_out_of_range_remains_unknown(self):
        data = parse_cisco_ios("mmi polling-interval 65536\nmmi snmp-timeout 1801\n")
        self.assertEqual(len(data["platform_commands"]), 2)
        self.assertTrue(all(x["structured"] is None for x in data["platform_commands"]))

    def test_no_mmi_pvc_not_misreported_as_no_default_pvc(self):
        data = parse_cisco_ios("no mmi pvc\n")
        item = data["platform_commands"][0]["structured"]
        self.assertEqual(item["feature"], "mmi_custom_pvc_configured")
        self.assertFalse(item["configured_value"])
        self.assertIn("default PVC", item["documented_meaning"])

    def test_ir_separates_known_meaning_from_platform_applicability(self):
        ir = normalize_cisco_ios(parse_cisco_ios("version 15.9\nmmi polling-interval 60\n"))
        self.assertEqual(ir["diagnostics"]["platform_semantics_unverified_count"], 0)
        self.assertEqual(ir["diagnostics"]["platform_scope_limited_count"], 1)
        self.assertEqual(ir["diagnostics"]["status"], "partial")

    def test_ios_15_header_is_inferred_not_attested(self):
        report = audit_text("Building configuration...\nversion 15.9\nhostname CE1\n",
                            file="CE1.cfg")
        self.assertEqual(report["source_format"], "ios_15_classic_syntax_inferred")
        self.assertEqual(report["format_confidence"], "high")
        self.assertTrue(report["ios_family_compatible"])
        self.assertFalse(report["device_os_identity_verified"])

    def test_xr_header_not_accepted_as_ios(self):
        report = audit_text("!! IOS XR Configuration 7.8.2\nhostname PE1\n",
                            file="PE1.cfg")
        self.assertEqual(report["source_format"], "ios_xr_header_confirmed")
        self.assertFalse(report["ios_family_compatible"])

    def test_xr_syntax_not_accepted_as_ios(self):
        report = audit_text("hostname PE1\nrouter static\ninterface MgmtEth0/RP0/CPU0/0\n",
                            file="PE1.cfg")
        self.assertEqual(report["source_format"], "ios_xr_syntax_inferred")
        self.assertFalse(report["ios_family_compatible"])

    def test_partial_ios_fragment_weak_evidence(self):
        report = audit_text("hostname R1\ninterface Ethernet0/0\n ip address 192.0.2.1 255.255.255.0\n",
                            file="fragment.txt")
        self.assertEqual(report["source_format"], "ios_like_fragment_inferred")
        self.assertEqual(report["format_confidence"], "medium")

    def test_unknown_without_evidence_is_not_claimed_ios(self):
        report = audit_text("hostname sample\n", file="unknown.cfg")
        self.assertEqual(report["source_format"], "undetermined")
        self.assertFalse(report["ios_family_compatible"])

    def test_unindented_line_logging_recovered_and_flagged(self):
        config = "hostname CE1\nline con 0\nlogging synchronous\nline aux 0\n login local\n"
        parsed = parse_cisco_ios(config)
        self.assertTrue(parsed["lines"][0]["logging_synchronous"])
        self.assertEqual(len(parsed["formatting_recoveries"]), 1)
        report = audit_text(config, file="CE1.cfg")
        self.assertEqual(report["nested_opaque_count"], 0)
        self.assertEqual(report["formatting_recovery_count"], 1)

    def test_no_recovery_without_line_scope(self):
        parsed = parse_cisco_ios("logging synchronous\n")
        self.assertFalse(parsed.get("formatting_recoveries"))
        self.assertEqual(len(parsed["syslog"]["other_commands"]), 1)


if __name__ == "__main__":
    unittest.main()
