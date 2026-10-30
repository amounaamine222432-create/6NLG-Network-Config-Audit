"""Régressions sur la normalisation SRX display-set et les options de routage.

Le *parsing* des commandes set est fourni par clijson (bibliothèque importée).
"""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from jsonschema import Draft202012Validator

from normalizers.policy_ir_v2 import normalize_juniper_junos_v2


SCHEMA = Path(__file__).resolve().parents[1] / "schemas/network_device_ir_v2.schema.json"


def evaluate(text: str, suffix: str = ".cfg") -> dict:
    with TemporaryDirectory() as folder:
        file = Path(folder) / ("test" + suffix)
        file.write_text(text, encoding="utf-8")
        return normalize_juniper_junos_v2(file)


class JunosDisplaySetV22(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.validator = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))

    def valid(self, ir: dict) -> None:
        errors = list(self.validator.iter_errors(ir))
        self.assertFalse(errors, [str(e) for e in errors[:2]])

    def test_set_is_parsed_with_clijson_and_schema_valid(self):
        config = """set system host-name SRX-EXAMPLE
set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24
set routing-options static route 0.0.0.0/0 next-hop 192.0.2.254
set protocols bgp group external type external
set protocols bgp group external peer-as 65001
set protocols bgp group external neighbor 192.0.2.2 peer-as 65001
"""
        ir = evaluate(config)
        self.valid(ir)
        self.assertEqual(ir["source"]["parser_schema_version"], "clijson-0.6.1")
        self.assertEqual(ir["device"]["hostname"], "SRX-EXAMPLE")
        self.assertEqual(ir["interfaces"][0]["ipv4_addresses"][0]["cidr"], "192.0.2.1/24")
        self.assertEqual(ir["routing"]["static_routes"][0]["next_hop"], "192.0.2.254")
        self.assertEqual(ir["routing"]["bgp"][0]["neighbors"][0]["remote_as"], 65001)

    def test_set_and_hierarchical_are_semantically_comparable(self):
        set_config = """set system host-name EDGE
set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 passive
set routing-instances RED instance-type vrf
set routing-instances RED interface ge-0/0/0.0
"""
        brace_config = """system {
 host-name EDGE;
}
protocols {
 ospf {
  area 0.0.0.0 {
   interface ge-0/0/1.0 {
    passive;
   }
  }
 }
}
routing-instances {
 RED {
  instance-type vrf;
  interface ge-0/0/0.0;
 }
}
"""
        one, two = evaluate(set_config), evaluate(brace_config)
        self.valid(one)
        self.valid(two)
        self.assertEqual(one["device"]["hostname"], two["device"]["hostname"])
        self.assertEqual(one["vrfs"][0]["name"], two["vrfs"][0]["name"])
        self.assertEqual(one["routing"]["ospf"][0]["passive_interfaces"],
                         two["routing"]["ospf"][0]["passive_interfaces"])

    def test_advanced_bgp_ospf_vrf(self):
        config = """set protocols bgp group PEERS hold-time 90
set protocols bgp group PEERS remove-private
set protocols bgp group PEERS authentication-key SHOULD_NOT_LEAK
set protocols bgp group PEERS neighbor 198.51.100.2 hold-time 30
set protocols ospf export REDISTRIBUTE-STATIC
set protocols ospf area 0.0.0.1 stub no-summaries
set protocols ospf area 0.0.0.1 interface ge-0/0/1.0 metric 20
set protocols ospf area 0.0.0.1 interface ge-0/0/1.0 hello-interval 5
set routing-instances CUSTOMER instance-type vrf
set routing-instances CUSTOMER interface ge-0/0/2.0
set routing-instances CUSTOMER vrf-target target:65000:120
set routing-instances CUSTOMER route-distinguisher 192.0.2.1:120
"""
        ir = evaluate(config)
        self.valid(ir)
        self.assertNotIn("SHOULD_NOT_LEAK", json.dumps(ir))
        bgp = ir["junos_details"]["protocols"]["bgp"]["groups"][0]
        self.assertEqual(bgp["hold_time_seconds"], 90)
        self.assertTrue(bgp["remove_private_configured"])
        self.assertTrue(bgp["authentication_secret_redacted"])
        self.assertEqual(bgp["neighbors"][0]["hold_time_seconds"], 30)
        ospf = ir["junos_details"]["protocols"]["ospf"]
        self.assertEqual(ospf["export_policies"], ["REDISTRIBUTE-STATIC"])
        self.assertEqual(ospf["areas"][0]["interfaces"][0]["metric"], 20)
        vrf = ir["junos_details"]["routing_instances"][0]
        self.assertEqual(vrf["vrf_target"], "target:65000:120")
        self.assertIn("ge-0/0/2.0", vrf["interfaces"])

    def test_srx_security_policy_nat_and_screens(self):
        config = """set security zones security-zone trust host-inbound-traffic system-services ssh
set security zones security-zone trust interfaces ge-0/0/0.0
set security policies from-zone trust to-zone untrust policy ALLOW match source-address any
set security policies from-zone trust to-zone untrust policy ALLOW match destination-address any
set security policies from-zone trust to-zone untrust policy ALLOW then permit
set security nat source rule-set OUT from zone trust
set security nat source rule-set OUT to zone untrust
set security nat source rule-set OUT rule PAT match source-address 10.0.0.0/8
set security nat source rule-set OUT rule PAT then source-nat interface
set security screen ids-option WAN icmp ping-death
set security screen ids-option WAN tcp syn-flood attack-threshold 200
"""
        ir = evaluate(config)
        self.valid(ir)
        sec = ir["junos_details"]["auxiliary"]["security"]
        self.assertEqual(sec["policies"][0]["configured_action"], "permit")
        self.assertEqual(sec["source_nat_rules"][0]["translation"], "interface")
        self.assertEqual(sec["screens"][0]["syn_flood"]["attack_threshold"], 200)
        self.assertIn("icmp.ping-death", sec["screens"][0]["checks"])

    def test_markdown_srx_placeholders_are_not_live_config(self):
        ir = evaluate("# Example\n\nset system host-name <string>\nset system login user demo authentication encrypted-password NEVER_EXPORT\n", ".md")
        self.valid(ir)
        self.assertIsNone(ir["device"]["hostname"])
        self.assertNotIn("NEVER_EXPORT", json.dumps(ir))
        self.assertTrue(any("Markdown" in n for n in ir["diagnostics"]["notes"]))

    def test_malformed_set_is_rejected_instead_of_silently_discarded(self):
        with self.assertRaises(ValueError):
            evaluate("set system host-name SRX\ndelete system host-name SRX\n")
        with self.assertRaises(ValueError):
            evaluate("set system host-name SRX\nUNEXPECTED EXTRA TEXT\n")

    def test_invalid_numbers_remain_unmodeled(self):
        ir = evaluate("set protocols bgp group EDGE hold-time 0\n"
                      "set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 metric -2\n")
        self.valid(ir)
        self.assertNotIn("hold_time_seconds", ir["junos_details"]["protocols"]["bgp"]["groups"][0])
        self.assertGreater(ir["diagnostics"]["source_only_counts"]
                           ["junos_v2_feature_unmodeled_by_section"]["protocols"], 0)


if __name__ == "__main__":
    unittest.main()
