"""Security and output contracts for the CIS fault summary and config preview."""

from __future__ import annotations

import csv
import importlib.util
from io import StringIO
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "webapp" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


redacted_ios_preview = load_module("cis_config_preview").redacted_ios_preview
failure_summary_csv = load_module("cis_failure_summary").failure_summary_csv


class CisNewExports(unittest.TestCase):
    def test_sensitive_commands_and_unknown_directives_are_masked(self):
        secrets = [
            "enable secret 5 PRIVATE-ONE",
            "username root password 7 PRIVATE-TWO",
            "neighbor 203.0.113.8 password PRIVATE-THREE",
            "ntp authentication-key 1 md5 PRIVATE-FOUR",
            "snmp-server community PRIVATE-FIVE RW",
            "key-string PRIVATE-SIX",
            "banner motd ^CPRIVATE-SEVEN^C",
            "description PRIVATE-EIGHT",
            "custom-directive PRIVATE-NINE",
            "ip ospf message-digest-key 1 md5 PRIVATE-TEN",
        ]
        lines = ["version 15.2", "interface GigabitEthernet0/0", *secrets,
                 "no ip proxy-arp", "transport input ssh"]
        shown = redacted_ios_preview("\n".join(lines))
        text = "\n".join(row["text"] for row in shown)
        for index in range(1, 11):
            self.assertNotIn(f"PRIVATE-{('ONE','TWO','THREE','FOUR','FIVE','SIX','SEVEN','EIGHT','NINE','TEN')[index-1]}", text)
        self.assertIn("interface GigabitEthernet0/0", text)
        self.assertIn("no ip proxy-arp", text)
        self.assertEqual(shown[1]["number"], 2)
        self.assertGreaterEqual(text.count("MASQUÉE"), 8)

    def test_preview_is_bounded(self):
        lines = redacted_ios_preview("no ip proxy-arp\n" * 10, max_lines=3)
        self.assertEqual(len(lines), 4)
        self.assertEqual(lines[-1]["text"], "[SUITE NON AFFICHÉE]")

    def test_failures_csv_includes_only_fail_findings(self):
        report = {"findings": [
            {"cis_control_id": "1.2.2", "status": "FAIL", "title": "VTY SSH",
             "observed_summary": "Telnet autorisé", "risk_level": "HIGH",
             "source_location": "ligne 13", "remediation": "Autoriser SSH",
             "verification_command": "show running-config | section line vty"},
            {"cis_control_id": "1.1.1", "status": "PASS", "title": "AAA"},
            {"cis_control_id": "2.3.1.1", "status": "UNKNOWN", "title": "NTP"},
        ]}
        raw = failure_summary_csv(report)
        self.assertTrue(raw.startswith(b"\xef\xbb\xbf"))
        rows = list(csv.reader(StringIO(raw.decode("utf-8-sig")), delimiter=";"))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1][0], "1.2.2")
        self.assertEqual(rows[1][2], "Telnet autorisé")
        self.assertEqual(rows[1][5], "Autoriser SSH")

    def test_network_review_is_reported_separately(self):
        report = {"findings": [], "network_coherence": {"findings": [
            {"rule_id": "ROUTE_CONFLICT", "status": "REVIEW", "severity": "MEDIUM",
             "description": "Routes concurrentes", "recommendation": "Contrôler les distances"},
            {"rule_id": "UNUSED_ACL", "status": "PASS"},
        ]}}
        rows = list(csv.reader(StringIO(failure_summary_csv(report).decode("utf-8-sig")), delimiter=";"))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1][0], "RESEAU")
        self.assertEqual(rows[1][1], "ROUTE_CONFLICT")

    def test_html_and_frontend_offer_both_features(self):
        root = Path(__file__).resolve().parents[1]
        template = (root / "webapp/templates/report_cis_ios.html").read_text()
        index = (root / "webapp/templates/index.html").read_text()
        js = (root / "webapp/static/js/cis_audit.js").read_text()
        self.assertIn('id="configuration-importee"', template)
        self.assertIn('id="controle-defaillants"', template)
        self.assertIn('id="cisFailuresCsv"', index)
        self.assertIn('id="cisConfigPreview"', index)
        self.assertIn('data.downloads.failures_html', js)


if __name__ == "__main__":
    unittest.main()
