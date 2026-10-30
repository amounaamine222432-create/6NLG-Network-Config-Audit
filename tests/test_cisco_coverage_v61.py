"""Tests de couverture additionnelle sans effacer les commandes inconnues."""

import json
from pathlib import Path
import unittest

from cisco_parser import parse_cisco_ios
from normalizers.cisco_normalizer import normalize_cisco_ios


class CiscoCoverageTests(unittest.TestCase):
    def test_batfish_global_extensions(self):
        config = """hostname TEST
no ip icmp rate-limit unreachable
ip tcp synwait-time 5
ip bgp-community new-format
aaa authentication login privilege-mode
ntp server 18.18.18.18
ntp server 23.23.23.23 prefer
"""
        parsed = parse_cisco_ios(config)
        self.assertEqual(parsed["unparsed_lines"], [])
        self.assertEqual(parsed["global_settings"]["tcp_synwait_seconds"], 5)
        self.assertFalse(parsed["global_settings"]["icmp_unreachable_rate_limit"]["enabled"])
        self.assertTrue(parsed["global_settings"]["bgp_community_new_format"])
        self.assertEqual(len(parsed["ntp"]["servers"]), 2)
        ir = normalize_cisco_ios(parsed)
        self.assertEqual(ir["services"]["ntp"]["servers"][0]["target"], "18.18.18.18")
        self.assertEqual(ir["services"]["ip_stack"]["tcp_synwait_seconds"], 5)

    def test_ssh_secret_variant_and_key_generation(self):
        secret = "UN_SECRET_DE_TEST_NEVERSHOW_123"
        config = ("enable secret " + secret + "\n"
                  "enable password AUTRE_SECRET\n"
                  "ip domain-name lab.example.com\n"
                  "crypto key generate rsa modulus 2048\n")
        parsed = parse_cisco_ios(config)
        self.assertEqual(parsed["unparsed_lines"], [])
        self.assertEqual(parsed["global_settings"]["ip_domain_name"], "lab.example.com")
        ir = normalize_cisco_ios(parsed)
        self.assertTrue(ir["management"]["enable_secret_configured"])
        self.assertEqual(ir["management"]["rsa_key_generation_requests"][0]["modulus"], 2048)
        self.assertNotIn(secret, json.dumps(ir))
        self.assertNotIn("AUTRE_SECRET", json.dumps(ir))

    def test_ntp_authentication_redacted(self):
        secret = "VERY_PRIVATE_NTP_SECRET_57"
        parsed = parse_cisco_ios("\n".join([
            "ntp authenticate",
            "ntp authentication-key 10 md5 " + secret + " 7",
            "ntp trusted-key 10",
            "ntp server vrf MGMT pool.example.com source Loopback10 prefer key 10 version 4",
            "ntp access-group peer 99",
            "ntp master 5",
        ]))
        self.assertEqual(parsed["unparsed_lines"], [])
        ir = normalize_cisco_ios(parsed)
        ntp = ir["services"]["ntp"]
        self.assertTrue(ntp["authentication_enabled"])
        self.assertEqual(ntp["authentication_key_count"], 1)
        self.assertEqual(ntp["master_stratum"], 5)
        self.assertEqual(ntp["servers"][0]["vrf"], "MGMT")
        self.assertTrue(ntp["servers"][0]["authentication_key_referenced"])
        self.assertNotIn(secret, json.dumps(parsed))
        self.assertNotIn(secret, json.dumps(ir))

    def test_unknown_and_malformed_remain_visible(self):
        parsed = parse_cisco_ios("ntp frobnicate unexpected\nntp server\nip tcp synwait-time invalid\n")
        self.assertEqual(len(parsed["unparsed_lines"]), 3)
        ir = normalize_cisco_ios(parsed)
        self.assertEqual(ir["diagnostics"]["unparsed_global_count"], 3)

    def test_ntp_unknown_options_not_falsely_claimed_as_modeled(self):
        parsed = parse_cisco_ios("ntp server 198.51.100.2 iburst\n")
        ir = normalize_cisco_ios(parsed)
        self.assertEqual(ir["services"]["ntp"]["servers"][0]["unmodeled_token_count"], 1)
        self.assertEqual(ir["diagnostics"]["status"], "partial")

    def test_schema_has_new_fields(self):
        schema = json.loads((Path(__file__).resolve().parents[1] / "schemas" /
                             "network_device_ir_v1.schema.json").read_text())
        self.assertIn("ntp", schema["properties"]["services"]["properties"])
        self.assertIn("enable_secret_configured", schema["properties"]["management"]["properties"])


if __name__ == "__main__":
    unittest.main()
