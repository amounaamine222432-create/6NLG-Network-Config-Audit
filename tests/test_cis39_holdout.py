"""78 explicit reference assertions for the independent 6NLG A/B test pack."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

from parsers.cisco_parser import parse_cisco_ios
from normalizers.cisco_normalizer import normalize_cisco_ios
from audit_engine.cis15_engine import audit_cis_ios15
from audit_engine.network_coherence import audit_network_coherence


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "benchmark_cis39_holdout"
CATALOGUE = json.loads((ROOT / "benchmarks/rules/cisco_ios/cis_ios15_v4.1.1_phase5_lab.json")
                       .read_text(encoding="utf-8"))
EXPECTED_B_FAIL = {
    "1.2.2", "1.2.7", "1.2.9", "1.4.3", "1.5.4", "1.5.9", "2.1.1.2",
    "2.2.2", "2.2.5", "2.3.1.4", "3.1.1", "3.1.2", "3.1.3",
    "3.3.4.1", "1.2.4", "1.2.5", "3.2.1", "3.3.1.8", "3.3.1.9",
}


class HoldoutCisMatrix(unittest.TestCase):
    def test_78_expected_verdicts_and_network_diagnostics(self):
        for filename, expected_na, expected_fail, coherence in (
            ("6NLG_TEST_A_PERIMETRE_DURCI.cfg", {"1.5.4", "1.1.5"}, set(),
             {"ROUTE_CONFLICT": "PASS", "INVALID_DEFAULT_GATEWAY": "PASS",
              "ACL_RULE_SHADOWING": "UNKNOWN", "UNUSED_ACL": "PASS"}),
            ("6NLG_TEST_B_PERIMETRE_RISQUES.cfg", {"1.1.5"}, EXPECTED_B_FAIL,
             {"ROUTE_CONFLICT": "REVIEW", "INVALID_DEFAULT_GATEWAY": "REVIEW",
              "ACL_RULE_SHADOWING": "FAIL", "UNUSED_ACL": "REVIEW"}),
        ):
            with self.subTest(configuration=filename):
                raw = (FIXTURES / filename).read_bytes()
                parsed = parse_cisco_ios(raw.decode("utf-8"))
                ir = normalize_cisco_ios(parsed, source_file=filename,
                                          sha256=hashlib.sha256(raw).hexdigest())
                report = audit_cis_ios15(ir, CATALOGUE, profile="L2", complete_config=True,
                                         parsed=parsed,
                                         audit_context={"external_interfaces": ["GigabitEthernet0/0"]})
                expected = {r["control_id"]: "PASS" for r in CATALOGUE["rules"]}
                expected.update({cid: "NOT_APPLICABLE" for cid in expected_na})
                expected.update({cid: "FAIL" for cid in expected_fail})
                observed = {f["cis_control_id"]: f["status"] for f in report["findings"]}
                self.assertEqual(observed, expected)
                self.assertEqual(ir["diagnostics"]["unparsed_global_count"], 0)
                self.assertFalse(ir["diagnostics"].get("opaque_sections"))
                net = audit_network_coherence(ir, complete_config=True)
                observed_coherence = {f["rule_id"]: f["status"] for f in net["findings"]}
                self.assertEqual({key: observed_coherence[key] for key in coherence}, coherence)
                self.assertTrue({"OVERLAPPING_INTERFACE_SUBNETS", "UNDEFINED_ACL_BINDING",
                                 "OVERLAPPING_DHCP_POOLS"}.issubset(observed_coherence))


if __name__ == "__main__":
    unittest.main()
