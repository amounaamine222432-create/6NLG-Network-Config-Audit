"""Contrats de validation croisée parseur -> IR -> CIS et collecte SHOW."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import unittest

from audit_engine.cis15_engine import audit_cis_ios15
from audit_engine.show_evidence import (
    ALLOWED_SHOW_COMMANDS, attach_show_evidence, summarize_show_outputs,
)
from cisco_parser import parse_cisco_ios
from normalizers.cisco_normalizer import normalize_cisco_ios


ROOT = Path(__file__).resolve().parents[1]
CATALOG = json.loads((ROOT / "benchmarks/rules/cisco_ios/cis_ios15_v4.1.1_phase5_lab.json")
                     .read_text(encoding="utf-8"))
FIXTURES = ROOT / "data/cis_phase5"


def evaluate(name: str, *, complete: bool = False, external: bool = False):
    raw = (FIXTURES / name).read_bytes()
    parsed = parse_cisco_ios(raw.decode("utf-8"))
    ir = normalize_cisco_ios(parsed, source_file=name, sha256=hashlib.sha256(raw).hexdigest())
    report = audit_cis_ios15(ir, CATALOG, profile="L2", complete_config=complete,
                             parsed=parsed,
                             audit_context={"external_interfaces": ["GigabitEthernet0/0"] if external else []})
    by_id = {f["cis_control_id"]: f for f in report["findings"]}
    return parsed, ir, report, by_id


class Phase5Tests(unittest.TestCase):
    def test_catalogue_and_inventory(self):
        parsed, ir, report, by_id = evaluate("router_compliant.cfg", complete=True, external=True)
        self.assertEqual(len(CATALOG["rules"]), 39)
        self.assertEqual(len(by_id), 39)
        self.assertEqual(report["parsing_normalization_inventory"]["part_count"], 59)
        self.assertEqual(report["counts"]["FAIL"], 0)
        self.assertEqual(report["counts"]["UNKNOWN"], 0)
        self.assertEqual(report["counts"]["PASS"], 36)
        self.assertEqual(report["counts"]["NOT_APPLICABLE"], 3)
        self.assertEqual(len(ir["routing"]["eigrp"]), 1)
        self.assertTrue(ir["routing"]["key_chains"])

    def test_non_compliant_controls_fail_explicitly(self):
        _, _, report, by_id = evaluate("router_non_compliant.cfg", complete=False, external=True)
        for cid in ("1.1.1", "1.1.2", "1.1.3", "1.1.4", "1.1.6", "1.2.4", "1.2.5", "2.2.2",
                    "3.2.1", "3.3.1.8", "3.3.1.9", "3.3.2.2"):
            with self.subTest(control=cid):
                self.assertEqual(by_id[cid]["status"], "FAIL")
        self.assertEqual(by_id["3.2.2"]["status"], "PASS")  # ACL présente mais permissive
        self.assertGreater(report["counts"]["FAIL"], 10)

    def test_partial_must_preserve_unknown(self):
        _, _, report, by_id = evaluate("router_partial.cfg", complete=False)
        self.assertGreater(report["counts"]["UNKNOWN"], 20)
        for cid in ("1.1.2", "1.2.4", "3.2.1", "3.2.2", "3.3.1.8", "3.3.2.1"):
            self.assertEqual(by_id[cid]["status"], "UNKNOWN")

    def test_external_interface_must_be_explicitly_selected(self):
        _, _, _, by_id = evaluate("router_compliant.cfg", complete=True)
        self.assertEqual(by_id["3.2.1"]["status"], "UNKNOWN")
        self.assertEqual(by_id["3.2.2"]["status"], "UNKNOWN")

    def test_routing_passwords_are_redacted_in_parser_ir_and_report(self):
        parsed, ir, report, _ = evaluate("router_compliant.cfg", complete=True, external=True)
        for data in (parsed, ir, report):
            serialized = json.dumps(data)
            for secret in ("LAB_ONLY_EIGRP", "LAB_ONLY_OSPF", "LAB_ONLY_NTP", "LAB_ONLY_HASH"):
                self.assertNotIn(secret, serialized)

    def test_read_only_show_and_ssh_confirmation(self):
        self.assertTrue(all(cmd.startswith("show ") and "running-config" not in cmd
                            for cmd in ALLOWED_SHOW_COMMANDS))
        secret = "SENSITIVE_VALUE_MUST_NOT_PERSIST"
        summary = summarize_show_outputs({
            "show version": "R-PHASE5-PARTIAL uptime is 2 weeks\n" + secret,
            "show ip ssh": "SSH Enabled - version 2.0\n" + secret,
            "show ip ospf interface": "Message digest authentication enabled\n" + secret,
        }, hostname="R-PHASE5-PARTIAL", target="192.0.2.30",
           timestamp=datetime.now(timezone.utc).isoformat())
        self.assertNotIn(secret, json.dumps(summary))
        _, _, report, by_id = evaluate("router_partial.cfg")
        self.assertEqual(by_id["2.1.1.2"]["status"], "UNKNOWN")
        attach_show_evidence(report, summary)
        self.assertEqual(by_id["2.1.1.2"]["status"], "PASS")
        self.assertEqual(by_id["2.1.1.2"]["evidence"]["assessment_basis"], "operational_show")

    def test_untrusted_show_evidence_is_rejected(self):
        _, _, report, _ = evaluate("router_partial.cfg")
        other = summarize_show_outputs({"show ip ssh": "SSH Enabled - version 2.0"},
                                       hostname="WRONG", target="192.0.2.31")
        with self.assertRaises(ValueError):
            attach_show_evidence(report, other)
        with self.assertRaises(ValueError):
            summarize_show_outputs({"configure terminal": "anything"},
                                   hostname="R", target="192.0.2.1")

    def test_show_hostname_must_be_observed_not_only_claimed(self):
        _, _, report, by_id = evaluate("router_partial.cfg")
        claimed = summarize_show_outputs({"show ip ssh": "SSH Enabled - version 2.0"},
                                         hostname="R-PHASE5-PARTIAL", target="192.0.2.1")
        attach_show_evidence(report, claimed)
        self.assertFalse(claimed["hostname_verified"])
        self.assertEqual(by_id["2.1.1.2"]["status"], "UNKNOWN")
        claimed["observations"]["raw_session_log"] = "SENSITIVE_SECRET"
        with self.assertRaises(ValueError):
            attach_show_evidence(report, claimed)

    def test_stale_operational_evidence_never_promotes_unknown(self):
        _, _, report, by_id = evaluate("router_partial.cfg")
        show = summarize_show_outputs({
            "show version": "R-PHASE5-PARTIAL uptime is 3 days",
            "show ip ssh": "SSH Enabled - version 2.0",
        }, hostname="R-PHASE5-PARTIAL", target="192.0.2.31",
           timestamp="2020-01-01T00:00:00+00:00")
        attach_show_evidence(report, show)
        self.assertFalse(report["operational_evidence"]["evidence_fresh_24h"])
        self.assertEqual(by_id["2.1.1.2"]["status"], "UNKNOWN")

    def test_named_eigrp_and_md5_keys_are_secret_free(self):
        content = """version 15.9
hostname R-NAMED
key chain DEMO
 key 5
  key-string LAB_NAMED_SECRET
!
router eigrp ISP
 address-family ipv4 autonomous-system 10
 af-interface GigabitEthernet0/0
  authentication key-chain DEMO
  authentication mode md5
 exit-af-interface
!
"""
        parsed = parse_cisco_ios(content)
        ir = normalize_cisco_ios(parsed)
        self.assertEqual(len(ir["routing"]["eigrp"]), 1)
        self.assertEqual(ir["routing"]["eigrp"][0]["address_families"][0]["as"], "10")
        self.assertNotIn("LAB_NAMED_SECRET", json.dumps(parsed))
        self.assertNotIn("LAB_NAMED_SECRET", json.dumps(ir))


if __name__ == "__main__":
    unittest.main()
