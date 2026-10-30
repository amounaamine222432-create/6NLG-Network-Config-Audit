import unittest
import importlib.util
from pathlib import Path

module_path = Path(__file__).resolve().parents[1] / "webapp" / "cis_source_evidence.py"
spec = importlib.util.spec_from_file_location("cis_source_evidence_under_test", module_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
source_excerpts = module.source_excerpts


class SourceEvidenceTests(unittest.TestCase):
    def test_actual_lines_and_vty(self):
        content = "hostname R1\nline vty 0 4\n transport input ssh telnet\n"
        self.assertEqual(source_excerpts("vty_ssh_only", content), [
            {"line": 2, "command": "line vty 0 4"},
            {"line": 3, "command": "transport input ssh telnet"},
        ])

    def test_passwords_are_never_exported(self):
        content = ("enable secret 9 TOPSECRET\n"
                   "ntp authentication-key 5 md5 TOPSECRET\n"
                   "neighbor 192.0.2.1 password TOPSECRET\n"
                   "username admin secret 9 TOPSECRET\n"
                   "snmp-server community TOPSECRET RW\n")
        for check in ("enable_secret_present", "ntp_auth_keys", "bgp_neighbor_password",
                      "local_user_secrets", "snmp_no_rw"):
            output = source_excerpts(check, content)
            self.assertTrue(output, check)
            self.assertNotIn("TOPSECRET", str(output), check)

    def test_banners_are_redacted(self):
        self.assertEqual(source_excerpts("motd_banner", "banner motd ^Secret information^"), [
            {"line": 1, "command": "banner motd [CONTENU MASQUÉ]"}
        ])

    def test_unknown_check_yields_no_commands(self):
        self.assertEqual(source_excerpts("unsupported", "aaa new-model"), [])


if __name__ == "__main__":
    unittest.main()
