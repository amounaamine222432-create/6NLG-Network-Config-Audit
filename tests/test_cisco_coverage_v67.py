"""V6.7: explicit OSPF passive exceptions and safe BGP neighbor metadata."""

import json
import unittest

from cisco_parser import parse_cisco_ios
from normalizers.cisco_normalizer import normalize_cisco_ios
from scripts.audit_parser_coverage import audit_text


class CiscoCoverageV67(unittest.TestCase):
    def test_ospf_no_passive_interface_is_explicit_and_not_runtime_state(self):
        configuration = (
            "version 15.9\nhostname R-TEST\nrouter ospf 110\n"
            " passive-interface default\n"
            " no passive-interface GigabitEthernet0/0\n"
            " network 10.10.10.0 0.0.0.255 area 0\n"
        )
        parsed = parse_cisco_ios(configuration)
        ospf = parsed["ospf_processes"][0]
        self.assertEqual(ospf["passive_interfaces"], ["default"])
        self.assertEqual(ospf["non_passive_interfaces"], ["GigabitEthernet0/0"])
        self.assertEqual(ospf["other_commands"], [])

        ir = normalize_cisco_ios(parsed)
        self.assertEqual(ir["routing"]["ospf"][0]["non_passive_interfaces"],
                         ["GigabitEthernet0/0"])
        self.assertEqual(audit_text(configuration, file="ospf.cfg")["nested_opaque_count"], 0)

    def test_neighbor_description_only_presence_reaches_ir(self):
        secret_canary = "SECRET_CANARY_DO_NOT_EXPORT"
        configuration = (
            "version 15.9\nhostname R-TEST\nrouter bgp 65010\n"
            " neighbor 203.0.113.2 remote-as 65020\n"
            f" neighbor 203.0.113.2 description {secret_canary}\n"
            " neighbor 203.0.113.2 route-map RM-OUT out\n"
        )
        parsed = parse_cisco_ios(configuration)
        neighbor = parsed["bgp_processes"][0]["neighbors"][0]
        self.assertTrue(neighbor["description_configured"])
        self.assertEqual(neighbor["description_source_line"], 5)

        ir = normalize_cisco_ios(parsed)
        peer = ir["routing"]["bgp"][0]["neighbors"][0]
        self.assertTrue(peer["description_configured"])
        self.assertEqual(peer["description_source"], {"line": 5})
        self.assertEqual(peer["policies"][0]["policy_name"], "RM-OUT")
        self.assertNotIn(secret_canary, json.dumps(ir))
        self.assertEqual(audit_text(configuration, file="bgp.cfg")["nested_opaque_count"], 0)

    def test_invalid_neighbor_route_map_direction_is_not_accepted(self):
        configuration = (
            "router bgp 65010\n"
            " neighbor 203.0.113.2 remote-as 65020\n"
            " neighbor 203.0.113.2 route-map RM-OUT sideways\n"
        )
        neighbor = parse_cisco_ios(configuration)["bgp_processes"][0]["neighbors"][0]
        self.assertEqual(neighbor["route_maps"], [])
        self.assertEqual(audit_text(configuration, file="invalid.cfg")[
            "nested_opaque_by_scope"]["bgp-neighbor-unmodeled"], 1)

    def test_missing_ospf_interface_name_stays_unmodeled(self):
        configuration = "router ospf 110\n no passive-interface\n"
        self.assertEqual(audit_text(configuration, file="invalid.cfg")[
            "nested_opaque_by_scope"]["ospf"], 1)

    def test_bgp_neighbor_password_is_modeled_without_exposing_secret(self):
        configuration = (
            "router bgp 65010\n"
            " neighbor 203.0.113.2 remote-as 65020\n"
            " neighbor 203.0.113.2 password 7 DUMMY_NOT_A_SECRET\n"
        )
        audit = audit_text(configuration, file="bad.cfg")
        self.assertEqual(audit["nested_opaque_by_scope"].get("bgp-neighbor-unmodeled", 0), 0)
        self.assertTrue(parse_cisco_ios(configuration)["bgp_processes"][0]["neighbors"][0]
                        ["password_configured"])
        self.assertNotIn("DUMMY_NOT_A_SECRET", json.dumps(audit))
        self.assertNotIn("DUMMY_NOT_A_SECRET", json.dumps(parse_cisco_ios(configuration)))
        self.assertNotIn("DUMMY_NOT_A_SECRET", json.dumps(normalize_cisco_ios(
            parse_cisco_ios(configuration))))


if __name__ == "__main__":
    unittest.main()
