"""Regression contract for every mapped control and conservative context handling.

Run: PYTHONPATH=.:parsers:final_validation_6nlg python3 -m unittest \
    tests.test_cis39_regression -v
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

from audit_engine.cis15_engine import audit_cis_ios15
from audit_engine.cis15_phase5_checks import _acl_restriction
from parsers.cisco_parser import parse_cisco_ios
from normalizers.cisco_normalizer import normalize_cisco_ios


ROOT = Path(__file__).resolve().parents[1]
CATALOGUE = json.loads((ROOT / "benchmarks/rules/cisco_ios/cis_ios15_v4.1.1_phase5_lab.json")
                       .read_text(encoding="utf-8"))
EXPECTED_NA = {"1.5.4", "1.1.5"}
EXPECTED_RISK_FAILS = {
    "1.2.2", "1.5.9", "2.1.1.2", "2.2.2", "2.2.5",
    "2.3.1.3", "2.3.1.4", "3.1.1", "3.3.4.1",
}


class All39Controls(unittest.TestCase):
    def _audit(self, stem: str, *, complete: bool = True, external: bool = True):
        path = ROOT / "validation_reference_cis_39" / f"{stem}.cfg"
        raw = path.read_bytes()
        parsed = parse_cisco_ios(raw.decode("utf-8-sig"))
        ir = normalize_cisco_ios(parsed, source_file=path.name,
                                  sha256=hashlib.sha256(raw).hexdigest())
        return audit_cis_ios15(
            ir, CATALOGUE, profile="L2", complete_config=complete, parsed=parsed,
            audit_context={"external_interfaces": ["GigabitEthernet0/0"] if external else []},
        )

    def test_every_control_in_all_three_reference_configs(self):
        self.assertEqual(len(CATALOGUE["rules"]), 39)
        self.assertEqual(len({rule["check"] for rule in CATALOGUE["rules"]}), 39)
        for stem in ("R-CIS39-REFERENCE", "R-CIS39-BRANCH-SECURE",
                     "R-CIS39-CONTROLLED-RISKS"):
            report = self._audit(stem)
            expected = {rule["control_id"]: "PASS" for rule in CATALOGUE["rules"]}
            expected.update({cid: "NOT_APPLICABLE" for cid in EXPECTED_NA})
            if "RISKS" in stem:
                expected.update({cid: "FAIL" for cid in EXPECTED_RISK_FAILS})
            findings = {f["cis_control_id"]: f for f in report["findings"]}
            self.assertEqual(set(findings), set(expected))
            for cid, wanted in expected.items():
                with self.subTest(config=stem, control=cid):
                    finding = findings[cid]
                    self.assertEqual(finding["status"], wanted)
                    self.assertIn("assessment_basis", finding["evidence"])
                    self.assertEqual(finding["assessment_scope"], "static_configuration_lab")
                    self.assertFalse(finding["requires_manual_review"])
                    self.assertEqual(bool(finding["remediation"]), wanted == "FAIL")
            self.assertEqual(report["catalogue_coverage"]["mapped_rules"], 39)
            self.assertEqual(report["catalogue_coverage"]["unique_checks"], 39)

    def test_missing_wan_designation_does_not_pass(self):
        findings = {f["cis_control_id"]: f for f in
                    self._audit("R-CIS39-REFERENCE", external=False)["findings"]}
        for cid in ("3.2.1", "3.2.2"):
            self.assertEqual(findings[cid]["status"], "UNKNOWN")
            self.assertTrue(findings[cid]["requires_manual_review"])

    def test_partial_config_never_infers_absent_requirements(self):
        full = self._audit("R-CIS39-REFERENCE", complete=True)
        partial = self._audit("R-CIS39-REFERENCE", complete=False)
        self.assertEqual(len(full["findings"]), len(partial["findings"]))
        self.assertFalse(partial["complete_config_assumed"])

    def test_vty_acl_wildcards_and_unknowns(self):
        broad = {"entries": [{"action": "permit", "source_match": {
            "kind": "network_wildcard", "address": "0.0.0.0",
            "wildcard": "255.255.255.255"}}]}
        narrow = {"entries": [{"action": "permit", "source_match": {
            "kind": "network_wildcard", "address": "192.0.2.0",
            "wildcard": "0.0.0.255"}}]}
        unsupported = {"entries": [{"action": "permit", "source_match": {
            "kind": "unparsed"}}]}
        self.assertEqual(_acl_restriction(broad), "BROAD")
        self.assertEqual(_acl_restriction(narrow), "RESTRICTIVE")
        self.assertEqual(_acl_restriction(unsupported), "UNKNOWN")
        self.assertEqual(_acl_restriction({"entries": []}), "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
