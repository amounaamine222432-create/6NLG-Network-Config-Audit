"""Fonctions SRX additionnelles et limites de couverture (IR v2.3)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from jsonschema import Draft202012Validator

from normalizers.policy_ir_v2 import normalize_juniper_junos_v2


PROJECT = Path(__file__).resolve().parents[1]
SRX = Path(os.getenv("JUNIPER_SRX_CONFIG") or PROJECT.parent / "juniper_sources" /
           "juniper-srx-config" / "srx110h-va" / "config.md")


def _ir(content: str) -> dict:
    with TemporaryDirectory() as tmp:
        path = Path(tmp) / "example.cfg"
        path.write_text(content, encoding="utf-8")
        return normalize_juniper_junos_v2(path)


class JuniperSRXV23(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = Draft202012Validator(json.loads(
            (PROJECT / "schemas" / "network_device_ir_v2.schema.json").read_text(encoding="utf-8")))

    def valid(self, ir: dict) -> None:
        errors = list(self.schema.iter_errors(ir))
        self.assertFalse(errors, [str(e) for e in errors[:2]])

    def test_pppoe_pap_secrets_never_exported(self):
        ir = _ir("""set interfaces pt-1/0/0 vlan-tagging
set interfaces pt-1/0/0 vdsl-options vdsl-profile auto
set interfaces pt-1/0/0 unit 0 vlan-id 35
set interfaces pt-1/0/0 unit 0 encapsulation ppp-over-ether
set interfaces pp0 unit 0 ppp-options pap local-name NEVER_EXPORT_USERNAME
set interfaces pp0 unit 0 ppp-options pap local-password NEVER_EXPORT_PASSWORD
set interfaces pp0 unit 0 ppp-options pap passive
set interfaces pp0 unit 0 pppoe-options service-name NEVER_EXPORT_ISP
set interfaces pp0 unit 0 pppoe-options underlying-interface pt-1/0/0.0
set interfaces pp0 unit 0 pppoe-options auto-reconnect 5
set interfaces pp0 unit 0 pppoe-options client
set interfaces pp0 unit 0 family inet negotiate-address
""")
        self.valid(ir)
        text = json.dumps(ir)
        for secret in ("NEVER_EXPORT_USERNAME", "NEVER_EXPORT_PASSWORD", "NEVER_EXPORT_ISP"):
            self.assertNotIn(secret, text)
        entries = {entry["name"]: entry for entry in ir["junos_details"]["interfaces"]}
        pt = entries["pt-1/0/0.0"]
        self.assertEqual(pt["physical_settings"]["vdsl_profile"], "auto")
        self.assertEqual(pt["vlan_id"], 35)
        self.assertEqual(pt["encapsulation"], "ppp-over-ether")
        pp = entries["pp0.0"]
        self.assertTrue(pp["pap_authentication"]["secret_configured"])
        self.assertTrue(pp["pap_authentication"]["credentials_redacted"])
        self.assertEqual(pp["pppoe"]["auto_reconnect_seconds"], 5)
        self.assertTrue(pp["families"]["inet"]["negotiate_address_configured"])

    def test_interface_range_dhcp_and_ipv4(self):
        ir = _ir("""set interfaces interface-range LAN member fe-0/0/1
set interfaces interface-range LAN unit 0 family ethernet-switching vlan members LAN-VLAN
set interfaces fe-0/0/0 unit 0 family inet dhcp
set interfaces vlan unit 0 family inet address 192.0.2.1/24
""")
        self.valid(ir)
        ranges = ir["junos_details"]["auxiliary"]["interface_ranges"]
        self.assertEqual(ranges[0]["members"], ["fe-0/0/1"])
        self.assertEqual(ranges[0]["vlan_members"], ["LAN-VLAN"])
        ports = {entry["name"]: entry for entry in ir["junos_details"]["interfaces"]}
        self.assertTrue(ports["fe-0/0/0.0"]["families"]["inet"]["dhcp_configured"])
        self.assertIn("192.0.2.1/24", ports["vlan.0"]["families"]["inet"]["addresses"])

    def test_security_interface_inbound_mss(self):
        ir = _ir("""set security zones security-zone OUT interfaces fe-0/0/0.0 host-inbound-traffic system-services ssh
set security zones security-zone OUT interfaces fe-0/0/0.0 host-inbound-traffic protocols ospf
set security flow tcp-mss all-tcp mss 1452
""")
        self.valid(ir)
        sec = ir["junos_details"]["auxiliary"]["security"]
        self.assertEqual(sec["tcp_mss_all_tcp_bytes"], 1452)
        interface = sec["zones"][0]["interfaces"][0]
        self.assertEqual(interface["inbound_system_services"], ["ssh"])
        self.assertEqual(interface["inbound_protocols"], ["ospf"])

    def test_static_metric_is_not_cisco_administrative_distance(self):
        ir = _ir("""set routing-options static route 0.0.0.0/0 next-hop pp0.0
set routing-options static route 0.0.0.0/0 metric 100
set protocols stp
""")
        self.valid(ir)
        route = ir["junos_details"]["auxiliary"]["routing_options"]["static_routes"][0]
        self.assertEqual(route["next_hop"], "pp0.0")
        self.assertEqual(route["next_hop_kind"], "interface")
        self.assertEqual(route["metric"], 100)
        self.assertNotIn("administrative_distance", route)
        self.assertTrue(ir["junos_details"]["protocols"]["stp"]["configured"])

    def test_invalid_parameters_are_not_claimed_as_modeled(self):
        ir = _ir("""set interfaces pt-1/0/0 vdsl-options vdsl-profile unsupported
set interfaces pp0 unit 0 pppoe-options auto-reconnect -1
set security flow tcp-mss all-tcp mss 3
set routing-options static route 0.0.0.0/0 metric 4294967296
""")
        self.valid(ir)
        remaining = ir["diagnostics"]["source_only_counts"]["junos_v2_feature_unmodeled_by_section"]
        self.assertGreaterEqual(sum(remaining.values()), 4)

    def test_external_srx_excerpt_full_extension_coverage(self):
        if not SRX.exists():
            self.skipTest("Le corpus SRX public externe n'est pas présent")
        ir = normalize_juniper_junos_v2(SRX)
        self.valid(ir)
        stats = ir["diagnostics"]["source_only_counts"]
        remaining = stats["junos_v2_feature_unmodeled_by_section"]
        self.assertEqual(sum(remaining.values()), 0)
        self.assertEqual(sum(stats["junos_v2_feature_recognized_by_section"].values()), 57)
        # Un exemple de documentation n'est pas une configuration opérationnelle.
        self.assertEqual(ir["diagnostics"]["status"], "partial")
        self.assertIsNone(ir["device"]["hostname"])


if __name__ == "__main__":
    unittest.main()
