"""Tests de la restitution HTML/JSON du parseur V6."""

import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from report_validation import analyze_device, build_report, main, render_html


def sample(**overrides):
    data = {
        "vendor": "cisco_ios",
        "hostname": "R-TEST",
        "interfaces": [{"name": "GigabitEthernet0/0", "source_line": 1,
                        "ipv4_addresses": [{"address": "192.0.2.2", "mask": "255.255.255.0"}],
                        "administrative_command": "no shutdown", "vrf_forwarding": None,
                        "nat_role": "inside", "hsrp_groups": []}],
        "ospf_processes": [], "bgp_processes": [], "static_routes": [],
        "access_lists": [], "prefix_lists": [], "route_maps": [], "vrfs": [],
        "nat_rules": [], "dhcp_pools": [], "unparsed_lines": [],
        "platform_commands": [], "local_users": [], "lines": [],
        "global_settings": {"ios_version": "15.9", "http_server_enabled": False},
        "snmp": {"communities": [], "hosts": []},
        "syslog": {"hosts": [{"host": "192.0.2.99"}]},
    }
    data.update(overrides)
    return data


class ReportValidationTests(unittest.TestCase):
    def test_known_safe_properties(self):
        item = analyze_device(sample(), "R-TEST.cfg")
        codes = {f["code"]: f["level"] for f in item["findings"]}
        self.assertEqual(codes["HOSTNAME"], "success")
        self.assertEqual(codes["IPV4_VALID"], "success")
        self.assertEqual(codes["HTTP_SERVER"], "success")
        self.assertEqual(item["counts"]["interfaces"], 1)

    def test_invalid_ipv4_and_duplicate_interface(self):
        cfg = sample()
        cfg["interfaces"][0]["ipv4_addresses"][0]["mask"] = "255.0.999.0"
        cfg["interfaces"].append(dict(cfg["interfaces"][0]))
        codes = [f["code"] for f in analyze_device(cfg, "bad.cfg")["findings"]]
        self.assertIn("IPV4_INVALID", codes)
        self.assertIn("INTERFACE_DUPLICATE", codes)

    def test_snmp_secrets_never_leave_report(self):
        cfg = sample(
            snmp={"communities": [{"value": "S3CR3T_PRIVATE_DO_NOT_LOG", "access": "RW", "source_line": 6}],
                  "hosts": [{"host": "192.0.2.8", "version": "2c", "options": ["S3CR3T_PRIVATE_DO_NOT_LOG"], "source_line": 7}]},
            unparsed_lines=[{"line": 12, "command": "enable secret S3CR3T_PRIVATE_DO_NOT_LOG"}],
            local_users=[{"name": "S3CR3T_PRIVATE_DO_NOT_LOG", "credential_configured": True}],
        )
        item = analyze_device(cfg, "secure.cfg")
        report = {"generated_at": "DATE", "totals": {"devices": 1, "warnings": 3, "successes": 1, "unparsed_global": 1}, "devices": [item]}
        html = render_html(report)
        serialized = json.dumps(item, ensure_ascii=False)
        self.assertNotIn("S3CR3T_PRIVATE_DO_NOT_LOG", html)
        self.assertNotIn("S3CR3T_PRIVATE_DO_NOT_LOG", serialized)
        self.assertIn("SNMP_RW", serialized)
        self.assertIn("SNMP_LEGACY", serialized)

    def test_html_escapes_untrusted_names(self):
        name = "Routeur<script>alert(1)</script>"
        item = analyze_device(sample(hostname=name), "a<b>.cfg")
        report = {"generated_at": "DATE", "totals": {"devices": 1, "warnings": 0, "successes": 1, "unparsed_global": 0}, "devices": [item]}
        html = render_html(report)
        self.assertNotIn(name, html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("a&lt;b&gt;.cfg", html)

    def test_acl_telnet_http_and_policy_warnings(self):
        cfg = sample(
            lines=[{"identifier": "vty 0 4", "source_line": 8, "transport_input": ["telnet", "ssh"]}],
            global_settings={"http_server_enabled": True},
            access_lists=[{"name": "99", "entries": [{"action": "permit", "protocol": "ip", "source": {"kind": "any"}, "destination": {"kind": "any"}, "source_line": 9}]}],
            bgp_processes=[{"local_as": "65000", "neighbors": [{"id": "192.0.2.1", "source_line": 15, "remote_as": None, "route_maps": [{"name": "NO_SUCH_POLICY", "source_line": 16}]}]}],
        )
        codes = {f["code"] for f in analyze_device(cfg, "insecure.cfg")["findings"]}
        self.assertTrue({"TELNET", "HTTP_SERVER", "ACL_PERMIT_ANY", "BGP_REMOTE_AS", "BGP_POLICY_MISSING"}.issubset(codes))

    def test_nat_check_and_no_false_runtime_inference(self):
        cfg = sample(nat_rules=[{"kind": "list_pool"}])
        data = analyze_device(cfg, "nat.cfg")
        self.assertIn("NAT_ROLES", [f["code"] for f in data["findings"]])
        self.assertIn("warning", [f["level"] for f in data["findings"]])
        self.assertNotIn("interface opérationnelle", json.dumps(data))

    def test_json_source_batch_and_cli_writes_html(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "routers").mkdir()
            (root / "routers" / "one.json").write_text(json.dumps(sample()), encoding="utf-8")
            (root / "routers" / "two.json").write_text(json.dumps(sample(hostname="R2")), encoding="utf-8")
            generated = build_report(sorted((root / "routers").glob("*.json")), root / "routers")
            self.assertEqual(generated["totals"]["devices"], 2)
            output = root / "reports" / "audit.html"
            summary = root / "reports" / "summary.json"
            self.assertEqual(main([str(root / "routers"), "--output", str(output), "--json-summary", str(summary)]), 0)
            self.assertIn("R2", output.read_text(encoding="utf-8"))
            self.assertEqual(json.loads(summary.read_text(encoding="utf-8"))["totals"]["devices"], 2)


if __name__ == "__main__":
    unittest.main()
