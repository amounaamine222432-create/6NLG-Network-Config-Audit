"""Tests de l'interprétation traçable des 11 directives de plateforme observées."""

import json
import unittest

from cisco_parser import parse_cisco_ios
from normalizers.cisco_normalizer import normalize_cisco_ios
from scripts.audit_parser_coverage import audit_text


CORPUS = """hostname CE-1
boot-start-marker
boot-end-marker
multilink bundle-name authenticated
mmi polling-interval 60
no mmi auto-configure
no mmi pvc
mmi snmp-timeout 180
no scheduler allocate
no process cpu extended history
no process cpu autoprofile hog
no service-routing capabilities-manager
"""


class PlatformDirectivesV65(unittest.TestCase):
    def test_all_eleven_known_forms_are_structured(self):
        parsed = parse_cisco_ios(CORPUS)
        self.assertEqual(len(parsed["platform_commands"]), 11)
        self.assertTrue(all(isinstance(x["structured"], dict)
                            for x in parsed["platform_commands"]))
        keys = {x["structured"]["feature"] for x in parsed["platform_commands"]}
        self.assertEqual(len(keys), 11)

    def test_ir_all_directives_exposed_with_source(self):
        ir = normalize_cisco_ios(parse_cisco_ios(CORPUS))
        self.assertEqual(len(ir["device"]["platform_directives"]), 11)
        self.assertEqual(ir["diagnostics"]["platform_directive_count"], 11)
        self.assertEqual(ir["diagnostics"]["platform_modeled_count"], 11)
        self.assertEqual(ir["diagnostics"]["platform_opaque_count"], 0)
        self.assertEqual(ir["diagnostics"]["platform_semantics_unverified_count"], 0)
        self.assertEqual(ir["diagnostics"]["platform_scope_limited_count"], 4)
        self.assertEqual(ir["diagnostics"]["status"], "partial")
        self.assertEqual(ir["device"]["platform_directives"][0]["source"]["line"], 2)
        self.assertTrue(all(x["operational_state"] is None for x in ir["device"]["platform_directives"]))

    def test_mmi_numeric_values_with_vendor_documented_units_and_scope(self):
        ir = normalize_cisco_ios(parse_cisco_ios(CORPUS))
        features = {x["feature"]: x for x in ir["device"]["platform_directives"]}
        item = features["mmi_polling_interval_configured_value"]
        self.assertEqual(item["configured_value"], 60)
        self.assertEqual(item["value_unit"], "seconds")
        self.assertEqual(item["documentation_status"], "vendor_documented_platform_specific")
        self.assertEqual(item["documentation_reference"], "Cisco OL-2479-02")
        self.assertEqual(features["mmi_snmp_timeout_configured_value"]["configured_value"], 180)

    def test_boot_markers_are_not_claimed_executable(self):
        parsed = parse_cisco_ios(CORPUS)
        self.assertEqual(parsed["platform_commands"][0]["structured"]["feature"],
                         "boot_section_start_marker")
        self.assertTrue(parsed["platform_commands"][0]["structured"]["configured_value"])
        self.assertEqual(parsed["unparsed_lines"], [])

    def test_scheduler_custom_microseconds_both_values(self):
        ir = normalize_cisco_ios(parse_cisco_ios("scheduler allocate 20000 1000\n"))
        item = ir["device"]["platform_directives"][0]
        self.assertEqual(item["feature"], "scheduler_allocate_custom")
        self.assertEqual(item["configured_value"], {
            "interrupt_microseconds": 20000, "process_microseconds": 1000,
        })
        self.assertEqual(item["value_unit"], "microseconds")

    def test_bad_mmi_option_remains_unmodeled(self):
        report = audit_text("hostname R\nmmi polling-interval nonsense\n", file="X.cfg")
        self.assertEqual(report["source_only_counts"]["platform_commands"], 1)
        self.assertEqual(report["source_only_counts"]["platform_unmodeled"], 1)
        self.assertEqual(report["status"], "platform_syntax_not_modeled")
        ir = normalize_cisco_ios(parse_cisco_ios("mmi polling-interval nonsense\n"))
        self.assertEqual(ir["diagnostics"]["platform_opaque_count"], 1)

    def test_unsupported_multilink_variant_stays_unmodeled(self):
        report = audit_text("multilink bundle-name invented\n", file="X.cfg")
        self.assertEqual(report["source_only_counts"]["platform_unmodeled"], 1)

    def test_audit_separates_documented_legacy_scope(self):
        report = audit_text(CORPUS, file="CE-1.cfg")
        self.assertEqual(report["unparsed_global_count"], 0)
        self.assertEqual(report["nested_opaque_count"], 0)
        self.assertEqual(report["source_only_counts"]["platform_modeled"], 11)
        self.assertEqual(report["source_only_counts"]["platform_semantics_unverified"], 0)
        self.assertEqual(report["source_only_counts"]["platform_documented_scope_limited"], 4)
        self.assertEqual(report["status"], "platform_scope_review_pending")
        self.assertNotIn("boot-start-marker", json.dumps(report))

    def test_no_system_operational_inference(self):
        ir = normalize_cisco_ios(parse_cisco_ios(CORPUS))
        self.assertNotIn("cpu_current_usage", json.dumps(ir))
        self.assertNotIn("boot_image_loaded", json.dumps(ir))

    def test_legacy_parser_record_kept_as_unknown_platform(self):
        parsed = parse_cisco_ios("boot-start-marker\n")
        del parsed["platform_commands"][0]["structured"]
        ir = normalize_cisco_ios(parsed)
        self.assertEqual(ir["diagnostics"]["platform_opaque_count"], 1)
        self.assertEqual(ir["diagnostics"]["platform_modeled_count"], 0)


if __name__ == "__main__":
    unittest.main()
