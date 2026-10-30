"""Tests des 26 règles CIS IOS 15, y compris parsing et IR réels."""

import json
from pathlib import Path
import unittest

from audit_engine.cis15_engine import audit_cis_ios15
from cisco_parser import parse_cisco_ios
from normalizers.cisco_normalizer import normalize_cisco_ios


ROOT = Path(__file__).resolve().parents[1]
CATALOGUE = json.loads((ROOT / "benchmarks/rules/cisco_ios/cis_ios15_v4.1.1_extended_lab.json")
                       .read_text(encoding="utf-8"))
CANARY = "DEMO_CREDENTIAL_NEVER_EXPORT_123"

CONFIG_GOOD = f"""\
version 15.9
hostname R-LAB-CIS
aaa new-model
enable secret 5 {CANARY}
username operator privilege 1 secret 5 {CANARY}
ip ssh version 2
logging buffered 64000
logging host 192.0.2.10
logging trap informational
logging source-interface Loopback0
snmp-server community {CANARY} RO 10
snmp-server group NMS v3 priv
ntp authenticate
ntp authentication-key 1 md5 {CANARY}
ntp trusted-key 1
ntp server 192.0.2.123 key 1
ntp source Loopback0
no ip source-route
interface GigabitEthernet0/0
 no ip proxy-arp
!
interface Loopback0
 no ip proxy-arp
!
router bgp 65001
 neighbor 192.0.2.2 remote-as 65002
 neighbor 192.0.2.2 password {CANARY}
!
banner exec ^C
Acces reserve
^C
banner login ^C
Connexion reservee
^C
banner motd ^C
Avis legal
^C
line con 0
 exec-timeout 5 0
!
line vty 0 4
 exec-timeout 5 0
 transport input ssh
"""


def _audit(source: str, *, complete: bool = True, profile: str = "L2") -> tuple[dict, dict, dict]:
    parsed = parse_cisco_ios(source)
    ir = normalize_cisco_ios(parsed, source_file="test.cfg")
    return parsed, ir, audit_cis_ios15(ir, CATALOGUE, profile=profile,
                                       complete_config=complete, parsed=parsed)


def _finding(report: dict, rule_id: str) -> dict:
    return next(f for f in report["findings"] if f["cis_control_id"] == rule_id)


class TestCIS15Phase4(unittest.TestCase):
    def test_catalogue_verified_and_rule_ids_unique(self):
        self.assertEqual(len(CATALOGUE["rules"]), 26)
        self.assertEqual(len({r["control_id"] for r in CATALOGUE["rules"]}), 26)
        self.assertTrue(all(r["pdf_page"] > 0 and r["profile"] in {"L1", "L2"}
                            and r["review_status"] == "mapped_for_lab"
                            for r in CATALOGUE["rules"]))

    def test_26_controls_can_pass_on_explicit_test_configuration(self):
        parsed, ir, report = _audit(CONFIG_GOOD)
        self.assertEqual(report["counts"]["PASS"], 26, report["findings"])
        self.assertEqual(report["counts"]["FAIL"], 0)
        self.assertEqual(report["parsing_normalization_inventory"]["part_count"], 59)
        self.assertEqual(report["parsing_normalization_inventory"]["mapped_cis_rule_count"], 26)
        self.assertFalse(report["benchmark_conformance_certified"])
        self.assertNotIn(CANARY, json.dumps(ir))
        self.assertNotIn(CANARY, json.dumps(report))
        self.assertNotIn(CANARY, json.dumps(parsed))

    def test_l1_does_not_run_l2_requirements(self):
        _, _, report = _audit(CONFIG_GOOD, profile="L1")
        self.assertEqual(report["counts"]["PASS"], 17)
        self.assertEqual(report["counts"]["NOT_SELECTED"], 9)

    def test_negative_explicit_security_findings(self):
        altered = CONFIG_GOOD.replace("aaa new-model", "no aaa new-model")
        altered = altered.replace("transport input ssh", "transport input telnet")
        altered = altered.replace("exec-timeout 5 0", "exec-timeout 0 0")
        altered = altered.replace("ip ssh version 2", "ip ssh version 1")
        altered = altered.replace("privilege 1 secret", "privilege 1 password")
        altered = altered.replace(f"community {CANARY} RO", f"community {CANARY} RW")
        altered = altered.replace("group NMS v3 priv", "group NMS v3 auth")
        altered = altered.replace("logging trap informational", "logging trap warnings")
        altered = altered.replace("no ip source-route", "ip source-route")
        altered = altered.replace(" no ip proxy-arp", " ip proxy-arp", 1)
        altered += "interface Tunnel0\n ip address 10.0.0.1 255.255.255.252\n"
        _, _, report = _audit(altered)
        for control in ("1.1.1", "1.2.2", "1.2.7", "1.2.9", "1.4.3", "1.5.4",
                        "1.5.9", "2.1.1.2", "2.2.5", "3.1.1", "3.1.2", "3.1.3"):
            self.assertEqual(_finding(report, control)["status"], "FAIL", control)

    def test_missing_timeout_unknown_even_if_complete(self):
        altered = CONFIG_GOOD.replace(" exec-timeout 5 0\n", "")
        _, _, report = _audit(altered)
        self.assertEqual(_finding(report, "1.2.7")["status"], "UNKNOWN")
        self.assertEqual(_finding(report, "1.2.9")["status"], "UNKNOWN")

    def test_missing_ntp_key_is_not_false_noncompliance(self):
        altered = CONFIG_GOOD.replace(" key 1\n", "\n")
        _, _, partial = _audit(altered, complete=False)
        _, _, complete = _audit(altered, complete=True)
        self.assertEqual(_finding(partial, "2.3.1.4")["status"], "UNKNOWN")
        self.assertEqual(_finding(complete, "2.3.1.4")["status"], "FAIL")
        self.assertEqual(_finding(complete, "2.3.1.4")["evidence"]["assessment_basis"],
                         "assumed_absence")

    def test_bgp_peer_group_inheritance_without_disclosing_key(self):
        config = ("version 15.9\nhostname R-BGP\nrouter bgp 65001\n"
                  " neighbor PG peer-group\n"
                  f" neighbor PG password {CANARY}\n"
                  " neighbor 192.0.2.1 peer-group PG\n"
                  " neighbor 192.0.2.1 remote-as 65002\n")
        parsed, ir, report = _audit(config)
        self.assertEqual(_finding(report, "3.3.4.1")["status"], "PASS")
        peer = next(x for x in ir["routing"]["bgp"][0]["neighbors"] if x["kind"] == "peer")
        self.assertEqual(peer["password_inherited_from"], "PG")
        self.assertNotIn(CANARY, json.dumps(parsed))
        self.assertNotIn(CANARY, json.dumps(ir))

    def test_no_tunnel_without_full_config_stays_unknown(self):
        _, _, report = _audit(CONFIG_GOOD, complete=False)
        self.assertEqual(_finding(report, "3.1.3")["status"], "UNKNOWN")

    def test_no_tunnel_with_unparsed_global_is_unknown_even_if_complete(self):
        _, ir, _ = _audit(CONFIG_GOOD)
        ir["diagnostics"]["unparsed_global_count"] = 1
        report = audit_cis_ios15(ir, CATALOGUE, profile="L2", complete_config=True)
        self.assertEqual(_finding(report, "3.1.3")["status"], "UNKNOWN")
        self.assertIn("unparsed_global_commands", _finding(report, "3.1.3")
                      ["evidence"]["uncertainty_reasons"])


if __name__ == "__main__":
    unittest.main()
