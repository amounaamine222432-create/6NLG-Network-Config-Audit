"""Regression cases for the nine remaining C4Geeks nested IOS families.

All fixtures are synthetic and contain only disposable credentials.
"""

import json
import unittest

from cisco_parser import parse_cisco_ios
from normalizers.cisco_normalizer import normalize_cisco_ios
from scripts.audit_parser_coverage import audit_text


def _parse(text):
    return parse_cisco_ios("hostname R-V64\n" + text)


def _ir(text):
    return normalize_cisco_ios(_parse(text))


class IOSV64NestedTests(unittest.TestCase):
    def test_dhcp_lease_days_and_hours(self):
        parsed = _parse("ip dhcp pool USERS\n lease 0 12 30\n!")
        self.assertEqual(parsed["dhcp_pools"][0]["lease"]["duration_seconds"], 45000)
        self.assertEqual(parsed["dhcp_pools"][0]["other_commands"], [])
        lease = normalize_cisco_ios(parsed)["services"]["dhcp"]["pools"][0]["lease"]
        self.assertEqual(lease["duration_seconds"], 45000)
        self.assertFalse(lease["infinite"])

    def test_dhcp_lease_infinite_and_invalid_options(self):
        parsed = _parse("ip dhcp pool INF\n lease infinite\n!\n"
                        "ip dhcp pool BAD\n lease 1 24\n!")
        self.assertTrue(parsed["dhcp_pools"][0]["lease"]["infinite"])
        self.assertEqual(parsed["dhcp_pools"][1]["other_commands"], ["lease 1 24"])
        self.assertEqual(audit_text("hostname R\nip dhcp pool BAD\n lease 1 24", file="bad.cfg")
                         ["nested_opaque_count"], 1)

    def test_switchport_trunk_encapsulation_dot1q(self):
        text = "interface GigabitEthernet0/1\n switchport mode trunk\n switchport trunk encapsulation dot1q\n!"
        parsed = _parse(text)
        self.assertEqual(parsed["interfaces"][0]["switchport"]["trunk_encapsulation"], "dot1q")
        self.assertEqual(parsed["interfaces"][0]["other_commands"], [])
        self.assertEqual(normalize_cisco_ios(parsed)["interfaces"][0]["switchport"]["trunk_encapsulation"], "dot1q")

    def test_unknown_switchport_variant_not_silently_accepted(self):
        parsed = _parse("interface Gi0/1\n switchport trunk encapsulation unknown\n!")
        self.assertEqual(parsed["interfaces"][0]["other_commands"],
                         ["switchport trunk encapsulation unknown"])

    def test_snmp_location_contact_and_group(self):
        text = ("snmp-server location SECRET-BUILDING-3\n"
                "snmp-server contact secret-email@example.invalid\n"
                "snmp-server group NOC v3 priv read SAFE write SAFE access NOC-ACL\n")
        parsed = _parse(text)
        self.assertEqual(parsed["snmp"]["other_commands"], [])
        self.assertTrue(parsed["snmp"]["location_configured"])
        self.assertTrue(parsed["snmp"]["contact_configured"])
        self.assertEqual(parsed["snmp"]["groups"][0]["security_level"], "priv")
        ir = normalize_cisco_ios(parsed)
        self.assertTrue(ir["services"]["snmp"]["groups"][0]["access_restricted"])
        self.assertNotIn("SECRET-BUILDING-3", json.dumps(ir))
        self.assertNotIn("secret-email", json.dumps(ir))

    def test_snmp_v3_user_secrets_redacted(self):
        text = ("snmp-server user admin NOC v3 auth sha SUPER_AUTH_SECRET "
                "priv aes 128 SUPER_PRIV_SECRET access ALLOW-NOC\n")
        parsed = _parse(text)
        self.assertEqual(parsed["snmp"]["other_commands"], [])
        self.assertEqual(parsed["snmp"]["users"][0]["privacy_algorithm"], "aes-128")
        ir = normalize_cisco_ios(parsed)
        profile = ir["services"]["snmp"]["users"][0]
        self.assertTrue(profile["authentication_configured"])
        self.assertTrue(profile["privacy_configured"])
        self.assertTrue(profile["secrets_redacted"])
        self.assertNotIn("SUPER_AUTH_SECRET", json.dumps(ir))
        self.assertNotIn("SUPER_PRIV_SECRET", json.dumps(ir))
        self.assertNotIn("admin", json.dumps(ir))

    def test_snmp_traps_and_unrecognized_user_stay_accounted(self):
        text = ("snmp-server enable traps snmp authentication linkup linkdown\n"
                "snmp-server enable traps\n"
                "snmp-server user u G v3 auth sha MISSPELLED_SECRET weird-option\n")
        parsed = _parse(text)
        self.assertEqual(len(parsed["snmp"]["trap_rules"]), 2)
        self.assertEqual(len(parsed["snmp"]["other_commands"]), 1)
        ir = normalize_cisco_ios(parsed)
        self.assertEqual(len(ir["services"]["snmp"]["trap_rules"]), 2)
        self.assertNotIn("MISSPELLED_SECRET", json.dumps(ir))
        self.assertEqual(audit_text("hostname R\n" + text, file="snmp.cfg")["nested_opaque_count"], 1)

    def test_syslog_buffered_size_severity_and_discriminator(self):
        text = "logging buffered discriminator AUDIT 32768 warnings\n"
        ir = _ir(text)
        buffered = ir["services"]["syslog"]["buffered"]
        self.assertTrue(buffered["enabled"])
        self.assertEqual(buffered["size_bytes"], 32768)
        self.assertEqual(buffered["severity"], 4)
        self.assertTrue(buffered["discriminator_configured"])

    def test_syslog_buffered_no_and_invalid(self):
        self.assertFalse(_ir("no logging buffered\n")["services"]["syslog"]["buffered"]["enabled"])
        self.assertEqual(_parse("logging buffered 256 nonsense\n")["syslog"]["other_commands"],
                         ["logging buffered 256 nonsense"])

    def test_all_eight_observed_families_zero_opaque_when_valid(self):
        text = ("interface Gi0/1\n switchport trunk encapsulation dot1q\n!\n"
                "ip dhcp pool USERS\n lease 0 8\n!\n"
                "ip dhcp pool GUESTS\n lease infinite\n!\n"
                "snmp-server location HQ\n"
                "snmp-server contact help@example.invalid\n"
                "snmp-server group group1 v3 auth\n"
                "snmp-server user client group1 v3 auth sha TOKEN\n"
                "snmp-server enable traps snmp authentication\n"
                "logging buffered 8192 informational\n")
        result = audit_text("hostname R\n" + text, file="all.cfg")
        self.assertEqual(result["unparsed_global_count"], 0)
        self.assertEqual(result["nested_opaque_count"], 0)
        ir = _ir(text)
        self.assertEqual(ir["diagnostics"]["opaque_sections"], [])
        self.assertNotIn("TOKEN", json.dumps(ir))


if __name__ == "__main__":
    unittest.main()
