"""Non-regression des directives imbriquées courantes des corpus IOS."""

import unittest

from cisco_parser import parse_cisco_ios
from normalizers.cisco_normalizer import normalize_cisco_ios


class NestedIOSV63Tests(unittest.TestCase):
    def test_bgp_address_family_and_peer_settings(self):
        parsed = parse_cisco_ios("""hostname R1
router bgp 65000
 bgp log-neighbor-changes
 neighbor GROUP peer-group
 neighbor GROUP remote-as 65100
 address-family ipv4
  bgp dampening
  bgp additional-paths select all
  bgp additional-paths send receive
  maximum-paths eibgp 5
  aggregate-address 10.0.0.0 255.0.0.0 summary-only
  neighbor GROUP activate
  neighbor GROUP send-community
  neighbor GROUP advertise additional-paths all
  neighbor GROUP route-reflector-client
""")
        bgp = parsed["bgp_processes"][0]
        self.assertEqual(bgp["other_commands"], [])
        self.assertEqual(bgp["address_families"][0]["other_commands"], [])
        self.assertTrue(bgp["log_neighbor_changes"])
        self.assertEqual(bgp["address_families"][0]["maximum_paths_eibgp"], 5)
        ir = normalize_cisco_ios(parsed)
        process = ir["routing"]["bgp"][0]
        self.assertEqual(process["address_family_features"][0]["aggregates"][0]["prefix"], "10.0.0.0/8")
        self.assertTrue(process["address_family_features"][0]["dampening_configured"])
        peer = process["neighbors"][0]
        self.assertEqual(peer["send_community_by_family"]["ipv4"], "standard")
        self.assertIn("ipv4", peer["route_reflector_client_families"])

    def test_interface_acl_ospf_and_mtu(self):
        parsed = parse_cisco_ios("""interface GigabitEthernet0/0
 mtu 1800
 ip access-group 101 in
 ip ospf network point-to-point
router ospf 10
 default-information originate
""")
        self.assertEqual(parsed["interfaces"][0]["other_commands"], [])
        self.assertEqual(parsed["ospf_processes"][0]["other_commands"], [])
        ir = normalize_cisco_ios(parsed)
        self.assertEqual(ir["interfaces"][0]["link"]["mtu"], 1800)
        self.assertEqual(ir["interfaces"][0]["acl_bindings"], [{"name": "101", "direction": "in"}])
        self.assertEqual(ir["interfaces"][0]["ospf_network_type"], "point-to-point")
        self.assertTrue(ir["routing"]["ospf"][0]["default_information_originate"])

    def test_terminal_line_and_nat_timeout(self):
        parsed = parse_cisco_ios("""line vty 0 4
 privilege level 15
 stopbits 1
ip nat translation icmp-timeout 600
""")
        self.assertEqual(parsed["lines"][0]["other_commands"], [])
        self.assertEqual(parsed["nat_other_commands"], [])
        ir = normalize_cisco_ios(parsed)
        self.assertEqual(ir["management"]["terminal_lines"][0]["privilege_level"], 15)
        self.assertEqual(ir["services"]["nat"]["translation_timers"]["icmp_timeout_seconds"], 600)

    def test_invalid_new_directives_are_not_silently_accepted(self):
        parsed = parse_cisco_ios("""interface GigabitEthernet0/0
 ip access-group 101 sideways
router bgp 65000
 address-family ipv4
  maximum-paths eibgp invalid
""")
        self.assertEqual(parsed["interfaces"][0]["other_commands"], ["ip access-group 101 sideways"])
        self.assertEqual(parsed["bgp_processes"][0]["address_families"][0]["other_commands"],
                         ["maximum-paths eibgp invalid"])

    def test_batfish_route_map_community_and_redistribution(self):
        config = """ip community-list standard PUBLIC permit 65000:10
route-map OUT permit 10
 match ip address 101
 match community PUBLIC
 set community 65000:10 additive
 set metric 50
router ospf 10
 redistribute connected subnets
"""
        ir = normalize_cisco_ios(parse_cisco_ios(config))
        operations = ir["policies"]["route_maps"][0]["entries"][0]["operations"]
        self.assertEqual([operation["operation"] for operation in operations], [
            "match_acl", "match_community_list", "set_bgp_communities", "set_metric"
        ])
        self.assertTrue(operations[2]["additive"])
        self.assertEqual(ir["policies"]["community_lists"][0]["entries"][0]["communities"], ["65000:10"])
        self.assertEqual(ir["routing"]["ospf"][0]["redistribution_rules"], [
            {"source_protocol": "connected", "include_subnets": True}
        ])
        self.assertEqual(ir["diagnostics"]["opaque_sections"], [])
        self.assertEqual(ir["diagnostics"]["notes"], [])

    def test_xr_configuration_is_not_mislabeled_as_ios_ir(self):
        parsed = parse_cisco_ios("!! IOS XR Configuration 26.1.1\nhostname PE-1\nrouter static\n")
        self.assertEqual(parsed["source_cli_family"], "ios_xr")
        with self.assertRaisesRegex(ValueError, "IOS XR"):
            normalize_cisco_ios(parsed)


if __name__ == "__main__":
    unittest.main()
