"""Tests autonomes de la representation intermediaire Cisco IOS V6."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from cisco_parser import parse_cisco_ios
from normalizers.cisco_normalizer import normalize_cisco_ios, validate_ir, main


MINIMAL = """\
version 15.9
hostname TEST-IR
interface Loopback0
 ip address 10.1.1.1 255.255.255.255
!
interface GigabitEthernet0/0
 ip address 192.0.2.2 255.255.255.252
 shutdown
!
router ospf 1
 network 10.0.0.0 0.255.255.255 area 1
 passive-interface Loopback0
!
ip route 0.0.0.0 0.0.0.0 192.0.2.1
"""


class NormalizerTests(unittest.TestCase):
    def test_ir_basics_and_cidr(self):
        ir = normalize_cisco_ios(parse_cisco_ios(MINIMAL), source_file="test.cfg")
        self.assertEqual(ir["schema_version"], "1.0.0")
        self.assertEqual(ir["device"]["hostname"], "TEST-IR")
        self.assertEqual(ir["device"]["platform"]["family"], "ios")
        self.assertEqual(ir["interfaces"][0]["ipv4_addresses"][0]["cidr"], "10.1.1.1/32")
        self.assertEqual(ir["interfaces"][1]["ipv4_addresses"][0]["cidr"], "192.0.2.2/30")
        self.assertEqual(ir["routing"]["static_routes"][0]["prefix"], "0.0.0.0/0")
        validate_ir(ir)

    def test_admin_state_is_not_operational_state(self):
        ir = normalize_cisco_ios(parse_cisco_ios(MINIMAL))
        self.assertIsNone(ir["interfaces"][0]["admin_enabled"])
        self.assertFalse(ir["interfaces"][1]["admin_enabled"])
        self.assertTrue(all(i["operational_state"] is None for i in ir["interfaces"]))

    def test_ospf_selector_not_mistaken_for_advertised_route(self):
        ir = normalize_cisco_ios(parse_cisco_ios(MINIMAL))
        ospf = ir["routing"]["ospf"][0]
        self.assertEqual(ospf["process_id"], "1")
        self.assertEqual(ospf["network_selectors"], [
            {"address": "10.0.0.0", "wildcard": "0.255.255.255", "area": "1"}])

    def test_bgp_peer_group_inheritance_and_policy(self):
        config = """\
hostname BGP-IR
router bgp 65010
 neighbor ISP peer-group
 neighbor ISP remote-as 65020
 neighbor 198.51.100.1 peer-group ISP
 address-family ipv4
  neighbor 198.51.100.1 activate
  neighbor ISP route-map PREF_IN in
 exit-address-family
!
route-map PREF_IN permit 10
 match ip address prefix-list P
 set local-preference 200
"""
        ir = normalize_cisco_ios(parse_cisco_ios(config))
        bgp = ir["routing"]["bgp"][0]
        peer = next(x for x in bgp["neighbors"] if x["id"] == "198.51.100.1")
        group = next(x for x in bgp["neighbors"] if x["id"] == "ISP")
        self.assertEqual(peer["remote_as"], 65020)
        self.assertEqual(peer["remote_as_inherited_from"], "ISP")
        self.assertEqual(peer["session_type_configured"], "ebgp")
        self.assertEqual(group["policies"][0]["policy_name"], "PREF_IN")
        self.assertEqual(peer["inherited_policy_references"][0]["policy_name"], "PREF_IN")
        operations = ir["policies"]["route_maps"][0]["entries"][0]["operations"]
        self.assertEqual(operations[0]["references"], ["P"])
        self.assertEqual(operations[1], {"operation": "set_local_preference", "value": 200})

    def test_bgp_network_without_mask_does_not_assume_32(self):
        config = "hostname BGP-IR\nrouter bgp 65001\n network 10.0.0.0\n"
        ir = normalize_cisco_ios(parse_cisco_ios(config))
        self.assertIsNone(ir["routing"]["bgp"][0]["network_statements"][0]["prefix"])
        self.assertIn("Annonce BGP sans masque explicite", ir["diagnostics"]["notes"][0])

    def test_never_export_snmp_or_bgp_secrets(self):
        private = "SENSITIVE_FAKE_SECRET_DONT_EXPORT"
        config = f"""\
hostname SENSITIVE-DEVICE
snmp-server community {private} RO 10
router bgp 65001
 neighbor 192.0.2.1 remote-as 65002
 neighbor 192.0.2.1 password {private}
!
username admin privilege 15 secret 5 {private}
"""
        parsed = parse_cisco_ios(config)
        ir = normalize_cisco_ios(parsed)
        self.assertNotIn(private, json.dumps(ir))
        self.assertEqual(ir["services"]["snmp"]["communities"][0]["access"], "ro")
        self.assertTrue(ir["services"]["snmp"]["communities"][0]["secret_redacted"])
        self.assertEqual(ir["diagnostics"]["opaque_sections"], [])
        self.assertTrue(ir["routing"]["bgp"][0]["neighbors"][0]["password_configured"])

    def test_unknown_commands_referenced_without_raw_text(self):
        private = "DO_NOT_DISPLAY_THIS_LINE"
        config = f"hostname TEST\nunknown-global-secret {private}\ninterface Loopback0\n mystery-secret {private}\n"
        ir = normalize_cisco_ios(parse_cisco_ios(config))
        self.assertEqual(ir["diagnostics"]["unparsed_global_count"], 1)
        self.assertEqual(ir["diagnostics"]["unparsed_global_lines"], [2])
        self.assertEqual(ir["diagnostics"]["opaque_sections"][0]["section"], "interface:Loopback0")
        self.assertNotIn(private, json.dumps(ir))

    def test_invalid_ipv4_preserved_with_diagnostic(self):
        ir = normalize_cisco_ios(parse_cisco_ios("hostname R\ninterface Ethernet0/0\n ip address 10.0.0.1 255.0.999.0\n"))
        addr = ir["interfaces"][0]["ipv4_addresses"][0]
        self.assertEqual(addr["address"], "10.0.0.1")
        self.assertIsNone(addr["cidr"])
        self.assertEqual(ir["diagnostics"]["status"], "partial")
        self.assertTrue(ir["diagnostics"]["notes"])

    def test_unknown_vendor_rejected(self):
        with self.assertRaises(ValueError):
            normalize_cisco_ios({"vendor": "vyos"})

    def test_validation_rejects_wrong_root(self):
        with self.assertRaises(ValueError):
            validate_ir({"schema_version": "1.0.0"})

    def test_cli_file_and_batch_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "raw"
            (src / "edge").mkdir(parents=True)
            a = src / "edge" / "r1.cfg"
            a.write_text(MINIMAL, encoding="utf-8")
            b = src / "edge" / "r2.json"
            b.write_text(json.dumps(parse_cisco_ios(MINIMAL)), encoding="utf-8")
            output = root / "ir"
            self.assertEqual(main([str(src), "--output-dir", str(output)]), 0)
            first = json.loads((output / "edge" / "r1.ir.json").read_text(encoding="utf-8"))
            second = json.loads((output / "edge" / "r2.ir.json").read_text(encoding="utf-8"))
            self.assertEqual(first["source"]["file"], "edge/r1.cfg")
            self.assertEqual(first["device"], second["device"])
            self.assertEqual(len(first["source"]["sha256"]), 64)

    def test_no_live_session_or_acl_effectiveness_claims(self):
        ir = normalize_cisco_ios(parse_cisco_ios(MINIMAL))
        self.assertTrue(all(i["operational_state"] is None for i in ir["interfaces"]))
        self.assertNotIn("session_established", ir["routing"]["bgp"])
        self.assertEqual(ir["diagnostics"]["status"], "modeled_subset")


if __name__ == "__main__":
    unittest.main()
