"""Regression checks for six *Cisco IOS* CE fixtures from lab archives.

The provider-core IOS XR configurations are deliberately not part of this
corpus. These assertions verify extraction, not device reachability or policy.
"""

import unittest
from pathlib import Path

from cisco_parser import parse_cisco_ios


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "data" / "advanced_cases"

# Each case comes from a DIFFERENT laboratory archive.
CASES = {
    "isp_bgp_base/CE-1.cfg": ("CE-1A", 4, 0, 0, 1),
    "bgp_prepending/CE-1.cfg": ("CE-1A", 4, 0, 1, 1),
    "l3vpn_rr/CE1A.cfg": ("CE-1A", 5, 1, 0, 1),
    "l2vpn_vpls/CE-1.cfg": ("CE-1", 5, 0, 0, 0),
    "rsvp_te_ce/CE-1A.cfg": ("CE-1A", 5, 1, 0, 1),
    "segment_routing_ce/CE-1A.cfg": ("CE-1A", 5, 1, 0, 1),
}


class AdvancedLabTests(unittest.TestCase):
    def test_six_real_ios_customer_edge_files(self):
        for relative, (hostname, interface_count, ospf_count, route_count, vrf_count) in CASES.items():
            with self.subTest(lab=relative):
                path = FIXTURES / relative
                self.assertTrue(path.is_file(), f"Missing test input: {path}")
                parsed = parse_cisco_ios(path.read_text(encoding="utf-8-sig"))
                self.assertEqual(parsed["parser_schema_version"], "6.0")
                self.assertEqual(parsed["hostname"], hostname)
                self.assertEqual(len(parsed["interfaces"]), interface_count)
                self.assertEqual(len(parsed["ospf_processes"]), ospf_count)
                self.assertEqual(len(parsed["static_routes"]), route_count)
                self.assertEqual(len(parsed["vrfs"]), vrf_count)
                self.assertEqual(parsed["global_settings"]["ip_cef_enabled"], True)
                self.assertEqual(parsed["unparsed_lines"], [],
                                 "All top-level directives in the chosen cases should be classified")
                self.assertTrue(all(not iface["other_commands"] for iface in parsed["interfaces"]))
                for section in ("vrfs", "lines", "ospf_processes", "bgp_processes"):
                    self.assertTrue(all(not entry["other_commands"] for entry in parsed[section]),
                                    f"Unclassified nested commands in {section}")
                self.assertTrue(parsed["lines"], "Terminal-line config should be captured")
                self.assertTrue(parsed["global_settings"]["service_timestamps"] or
                                parsed["global_settings"]["service_commands"])
                if vrf_count:
                    self.assertEqual(parsed["vrfs"][0]["name"], "MGMT")
                    self.assertIn("ipv4", parsed["vrfs"][0]["address_families"])
                    mgmt_interface = next(i for i in parsed["interfaces"]
                                          if i["vrf_forwarding"] == "MGMT")
                    self.assertTrue(mgmt_interface["ipv4_dhcp"])

    def test_vrf_and_dhcp_syntax_variants(self):
        parsed = parse_cisco_ios("""\
version 15.9
vrf definition MGMT
 description management traffic
 rd 65000:1
 address-family ipv4
 exit-address-family
!
interface GigabitEthernet0/0
 vrf forwarding MGMT
 ip address dhcp
!
interface GigabitEthernet0/1
 ip vrf forwarding MGMT
 ip address dhcp hostname LAB-CE
!
ip domain name lab.invalid
no ip domain lookup
service timestamps log datetime msec
""")
        self.assertEqual(parsed["vrfs"][0]["rd"], "65000:1")
        self.assertEqual(parsed["vrfs"][0]["description"], "management traffic")
        self.assertEqual(parsed["vrfs"][0]["address_families"], ["ipv4"])
        self.assertEqual([i["vrf_forwarding"] for i in parsed["interfaces"]],
                         ["MGMT", "MGMT"])
        self.assertTrue(all(i["ipv4_dhcp"] for i in parsed["interfaces"]))
        self.assertEqual(parsed["interfaces"][1]["ipv4_dhcp_options"],
                         ["hostname", "LAB-CE"])
        self.assertEqual(parsed["global_settings"]["ip_domain_lookup_enabled"], False)
        self.assertEqual(parsed["global_settings"]["ip_domain_name"], "lab.invalid")
        self.assertEqual(parsed["global_settings"]["ios_version"], "15.9")

    def test_login_ssh_http_and_banner_capture(self):
        parsed = parse_cisco_ios("""\
hostname TEST-CE
username student privilege 15 secret 5 LAB_HASH_SHOULD_NOT_LEAK
no ip http server
no ip http secure-server
line vty 0 4
 login local
 transport input ssh
 exec-timeout 5 0
!
banner login ^CC
Welcome to this lab
^C
!
""")
        self.assertEqual(parsed["local_users"][0]["name"], "student")
        self.assertTrue(parsed["local_users"][0]["credential_configured"])
        self.assertNotIn("LAB_HASH_SHOULD_NOT_LEAK", repr(parsed))
        self.assertEqual(parsed["lines"][0]["transport_input"], ["ssh"])
        self.assertEqual(parsed["lines"][0]["login_method"], "local")
        self.assertEqual(parsed["lines"][0]["exec_timeout"], ["5", "0"])
        self.assertFalse(parsed["global_settings"]["http_server_enabled"])
        self.assertFalse(parsed["global_settings"]["https_server_enabled"])
        self.assertEqual(parsed["banners"][0]["kind"], "login")
        self.assertEqual(parsed["unparsed_lines"], [])


if __name__ == "__main__":
    unittest.main()
