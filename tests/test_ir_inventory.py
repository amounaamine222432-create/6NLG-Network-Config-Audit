"""Tests du chaînage des 53 parties de configuration IOS à l'IR."""

import json
from pathlib import Path
import unittest

from audit_engine.ir_inventory import build_ir_inventory
from audit_engine.cis15_engine import audit_cis_ios15
from cisco_parser import parse_cisco_ios
from normalizers.cisco_normalizer import normalize_cisco_ios


ROOT = Path(__file__).resolve().parents[1]
CATALOGUE = json.loads((ROOT / "benchmarks/rules/cisco_ios/cis_ios15_v4.1.1_lab.json")
                       .read_text(encoding="utf-8"))


class TestIRInventory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT / "data/advanced_cases/isp_bgp_base/CE-1.cfg"
        cls.source_text = path.read_text(encoding="utf-8")
        cls.parsed = parse_cisco_ios(cls.source_text)
        cls.ir = normalize_cisco_ios(cls.parsed, source_file=path.name)

    def test_all_main_sections_catalogued(self):
        inventory = build_ir_inventory(self.parsed, self.ir)
        self.assertEqual(inventory["part_count"], 59)
        self.assertEqual(inventory["group_count"], 11)
        self.assertEqual(inventory["audited_part_count"], 6)
        self.assertEqual(inventory["unaccounted_parser_roots"], [])
        groups = {p["group"] for p in inventory["parts"]}
        self.assertTrue({"reseau", "routage", "politiques", "services", "supervision",
                         "temps", "securite_ip", "administration"}.issubset(groups))

    def test_counts_are_entities_not_string_lengths(self):
        inventory = build_ir_inventory(self.parsed, self.ir)
        hostname = next(p for p in inventory["parts"] if p["part"] == "hostname")
        self.assertEqual(hostname["parser_count"], 1)
        self.assertEqual(hostname["ir_count"], 1)

    def test_inventory_distinguishes_non_audited_and_source_only(self):
        inventory = build_ir_inventory(self.parsed, self.ir)
        by_part = {p["part"]: p for p in inventory["parts"]}
        self.assertEqual(by_part["interfaces"]["status"], "IR_MAPPED")
        self.assertEqual(by_part["bannieres"]["status"], "AUDITED")
        self.assertEqual(by_part["metadonnees_config"]["status"], "SOURCE_ONLY")

    def test_engine_embeds_safe_inventory(self):
        result = audit_cis_ios15(self.ir, CATALOGUE, profile="L1", parsed=self.parsed)
        self.assertEqual(result["counts"]["PASS"], 2)
        self.assertEqual(result["parsing_normalization_inventory"]["part_count"], 59)
        encoded = json.dumps(result)
        self.assertNotIn(self.source_text, encoded)

    def test_unparsed_globals_block_inferred_fail_not_direct_fail(self):
        ir = json.loads(json.dumps(self.ir))
        ir["diagnostics"]["unparsed_global_count"] = 1
        result = audit_cis_ios15(ir, CATALOGUE, profile="L2", complete_config=True)
        self.assertEqual(result["counts"]["UNKNOWN"], 4)
        self.assertEqual(result["counts"]["PASS"], 2)
        ntp = next(x for x in result["findings"] if x["cis_control_id"] == "2.3.1.1")
        self.assertEqual(ntp["evidence"]["assessment_basis"], "assumed_absence")
        self.assertIn("unparsed_global_commands", ntp["evidence"]["uncertainty_reasons"])

    def test_explicit_telnet_is_fail_even_if_other_commands_unparsed(self):
        ir = json.loads(json.dumps(self.ir))
        vty_line = next(line for line in ir["management"]["terminal_lines"]
                        if line["line_id"].startswith("vty "))
        vty_line["transport_input"] = ["telnet"]
        ir["diagnostics"]["unparsed_global_count"] = 2
        result = audit_cis_ios15(ir, CATALOGUE, complete_config=True)
        vty = next(x for x in result["findings"] if x["cis_control_id"] == "1.2.2")
        self.assertEqual(vty["status"], "FAIL")
        self.assertEqual(vty["evidence"]["assessment_basis"], "explicit_ir")

    def test_unmodeled_vty_command_blocks_absence_fail(self):
        ir = json.loads(json.dumps(self.ir))
        vty_line = next(line for line in ir["management"]["terminal_lines"]
                        if line["line_id"].startswith("vty "))
        vty_line["transport_input"] = []
        ir["diagnostics"]["opaque_sections"] = [{"section": "line", "count": 1}]
        result = audit_cis_ios15(ir, CATALOGUE, complete_config=True)
        vty = next(x for x in result["findings"] if x["cis_control_id"] == "1.2.2")
        self.assertEqual(vty["status"], "UNKNOWN")
        self.assertIn("opaque_commands_in_related_section", vty["evidence"]["uncertainty_reasons"])


if __name__ == "__main__":
    unittest.main()
