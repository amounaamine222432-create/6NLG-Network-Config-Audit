"""Régression IR Junos v2.4 : couverture combinée sans double comptage."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from jsonschema import Draft202012Validator

from normalizers.policy_ir_v2 import normalize_juniper_junos_v2


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures_juniper_v24"


class JuniperCoverageUnionV24Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        schema = json.loads((ROOT / "schemas/network_device_ir_v2.schema.json").read_text())
        cls.validator = Draft202012Validator(schema)

    def _normalize(self, path: Path) -> dict:
        ir = normalize_juniper_junos_v2(path)
        self.assertFalse(list(self.validator.iter_errors(ir)), path.name)
        return ir

    def test_all_four_test_configs_have_no_combined_unknown_leaves(self):
        files = sorted(p for p in FIXTURES.iterdir() if p.name[:2] in {"01", "02", "03", "04"})
        self.assertEqual(len(files), 4)
        for path in files:
            with self.subTest(file=path.name):
                ir = self._normalize(path)
                counts = ir["diagnostics"]["source_only_counts"]
                self.assertGreater(counts["combined_total_leaves"], 0)
                self.assertEqual(counts["combined_unmodeled_leaves"], 0)
                self.assertEqual(counts["combined_modeled_leaves"], counts["combined_total_leaves"])
                # Les compteurs v1/v2 sont indépendants et peuvent rester positifs.
                self.assertEqual(ir["diagnostics"]["status"], "partial")

    def test_routing_vrf_and_bgp_stay_explicit(self):
        ir = self._normalize(FIXTURES / "04_JUNOS_COMPLET_ROUTAGE_VRF.conf")
        counts = ir["diagnostics"]["source_only_counts"]
        self.assertEqual((counts["combined_total_leaves"], counts["combined_modeled_leaves"]), (33, 33))
        self.assertEqual(ir["device"]["hostname"], "JN-CORE-04")
        self.assertEqual(len(ir["interfaces"]), 5)
        self.assertEqual(len(ir["routing"]["static_routes"]), 2)
        self.assertEqual(ir["vrfs"][0]["name"], "CLIENT-BLUE")
        self.assertEqual(ir["routing"]["bgp"][0]["neighbors"][0]["remote_as"], 64521)
        self.assertEqual(ir["routing"]["ospf"][0]["junos_interfaces_by_area"][0]["area"], "0.0.0.0")
        self.assertTrue(ir["junos_details"]["auxiliary"]["system"]["ssh_configured"])

    def test_junos_prefix_list_definition_and_reference(self):
        ir = self._normalize(FIXTURES / "04_JUNOS_COMPLET_ROUTAGE_VRF.conf")
        self.assertEqual(ir["policies"]["junos_prefix_lists"][0]["prefixes"], ["192.168.44.0/24"])
        route_policy = next(p for p in ir["policies"]["route_policies"] if p["name"] == "EXPORT-LAB")
        condition = route_policy["terms"][0]["conditions"][0]
        self.assertEqual(condition["kind"], "junos_prefix_list_reference")
        self.assertEqual(condition["values"], ["LAB-PREFIXES"])
        self.assertEqual(route_policy["terms"][0]["unmodeled_condition_count"], 0)
        self.assertEqual(ir["diagnostics"]["source_only_counts"]["policy_v2_unresolved_prefix_list_references"], 0)

    def test_srx_security_and_source_nat_from_display_set(self):
        ir = self._normalize(FIXTURES / "02_SRX_ACL_NAT_display_set.txt")
        sec = ir["junos_details"]["auxiliary"]["security"]
        self.assertEqual(len(sec["zones"]), 2)
        self.assertEqual(len(sec["policies"]), 2)
        self.assertEqual(sec["source_nat_rules"][0]["translation"], "interface")

    def test_prefix_list_filter_exact_longer_and_unrecognized_kept(self):
        config = """policy-options {
          prefix-list PL { 192.0.2.0/24; }
          policy-statement P {
            term T {
              from {
                prefix-list-filter PL orlonger;
                unknown-condition UNRECOGNIZED_TOKEN;
              }
              then accept;
            }
          }
        }
        """
        with TemporaryDirectory() as folder:
            path = Path(folder) / "unknown.conf"
            path.write_text(config, encoding="utf-8")
            ir = self._normalize(path)
        term = ir["policies"]["route_policies"][0]["terms"][0]
        self.assertEqual(term["conditions"][0]["kind"], "junos_prefix_list_filter")
        self.assertEqual(term["conditions"][0]["modifier"], "orlonger")
        self.assertEqual(term["unmodeled_condition_count"], 1)
        self.assertGreater(ir["diagnostics"]["source_only_counts"]["combined_unmodeled_leaves"], 0)
        self.assertNotIn("UNRECOGNIZED_TOKEN", json.dumps(ir))

    def test_unresolved_dynamic_apply_path_not_claimed_complete(self):
        config = """policy-options {
          prefix-list DYNAMIC {
            apply-path \"interfaces <*> unit <*> family inet address <*>\";
          }
          policy-statement P {
            term T {
              from {
                prefix-list DYNAMIC;
              }
              then accept;
            }
          }
        }
        """
        with TemporaryDirectory() as folder:
            path = Path(folder) / "dynamic.conf"
            path.write_text(config, encoding="utf-8")
            ir = self._normalize(path)
        counts = ir["diagnostics"]["source_only_counts"]
        self.assertEqual(ir["policies"]["junos_prefix_lists"], [])
        self.assertEqual(counts["policy_v2_unresolved_prefix_list_references"], 1)
        self.assertGreater(counts["combined_unmodeled_leaves"], 0)

    def test_unknown_top_level_does_not_leak_sensitive_section(self):
        secret = "SENSITIVE_CUSTOM_ROOT_444"
        with TemporaryDirectory() as folder:
            path = Path(folder) / "unknown.conf"
            path.write_text(f"{secret} {{\n unusual-value SECRET_VALUE_555;\n}}\n", encoding="utf-8")
            ir = self._normalize(path)
        serialized = json.dumps(ir)
        self.assertNotIn(secret, serialized)
        self.assertNotIn("SECRET_VALUE_555", serialized)
        self.assertIn("other", ir["diagnostics"]["source_only_counts"]["combined_unmodeled_by_section"])


if __name__ == "__main__":
    unittest.main()
