"""Régressions des faux verdicts identifiés pendant la revue 6NLG."""
import unittest

from parsers.cisco_parser import parse_cisco_ios
from normalizers.cisco_normalizer import normalize_cisco_ios
from audit_engine.cis15_phase5_checks import CHECKS, CONTEXT_CHECKS
from audit_engine.cis15_extended_checks import EXTENDED_CHECKS


def ir_of(body):
    return normalize_cisco_ios(parse_cisco_ios("version 15.2\nhostname TEST\n" + body + "\nend\n"))


class AuditCorrectionV68(unittest.TestCase):
    def test_two_eigrp_processes_on_distinct_interfaces_are_not_cross_multiplied(self):
        ir = ir_of("""key chain KEY
 key 1
  key-string DUMMY
interface GigabitEthernet0/0
 ip address 10.1.0.1 255.255.255.0
 ip authentication mode eigrp 10 md5
 ip authentication key-chain eigrp 10 KEY
interface GigabitEthernet0/1
 ip address 10.2.0.1 255.255.255.0
 ip authentication mode eigrp 20 md5
 ip authentication key-chain eigrp 20 KEY
router eigrp 10
 network 10.1.0.0 0.0.0.255
router eigrp 20
 network 10.2.0.0 0.0.0.255""")
        for name in ("eigrp_interface_keychain", "eigrp_interface_md5"):
            status, evidence = CHECKS[name](ir, True)
            self.assertEqual(status, "PASS")
            self.assertEqual(evidence["configured_authentication_interfaces"], 2)

    def test_unresolved_inbound_acl_is_not_pass(self):
        ir = ir_of("""interface GigabitEthernet0/0
 ip address 198.51.100.2 255.255.255.252
 ip access-group UNDEFINED in""")
        ctx = {"external_interfaces": ["GigabitEthernet0/0"]}
        self.assertEqual(CONTEXT_CHECKS["external_inbound_acl"](ir, False, ctx)[0], "UNKNOWN")
        self.assertEqual(CONTEXT_CHECKS["external_inbound_acl"](ir, True, ctx)[0], "FAIL")

    def test_vty_acl_creation_and_application_are_separate(self):
        ir = ir_of("""ip access-list standard VTY-MGMT
 permit host 10.1.1.10
 deny any
line vty 0 4
 transport input ssh""")
        # L'ACL existe, mais rien ne démontre sa destination VTY.
        self.assertEqual(CHECKS["vty_restricting_acl"](ir, True)[0], "UNKNOWN")
        self.assertEqual(CHECKS["vty_access_class"](ir, True)[0], "FAIL")
        applied = ir_of("""ip access-list standard VTY-MGMT
 permit host 10.1.1.10
 deny any
line vty 0 4
 access-class VTY-MGMT in
 transport input ssh""")
        self.assertEqual(CHECKS["vty_restricting_acl"](applied, True)[0], "PASS")
        self.assertEqual(CHECKS["vty_access_class"](applied, True)[0], "PASS")
        broad = ir_of("""ip access-list standard VTY-OPEN
 permit any
line vty 0 4
 access-class VTY-OPEN in
 transport input ssh""")
        self.assertEqual(CHECKS["vty_restricting_acl"](broad, True)[0], "FAIL")

    def test_ntp_key_must_exist_and_be_trusted(self):
        missing = ir_of("ntp server 192.0.2.10 key 99")
        self.assertEqual(EXTENDED_CHECKS["ntp_server_keys"](missing, False)[0], "UNKNOWN")
        self.assertEqual(EXTENDED_CHECKS["ntp_server_keys"](missing, True)[0], "FAIL")
        configured = ir_of("""ntp authenticate
ntp authentication-key 99 md5 DUMMY
ntp trusted-key 99
ntp server 192.0.2.10 key 99""")
        self.assertEqual(EXTENDED_CHECKS["ntp_server_keys"](configured, True)[0], "PASS")
        self.assertEqual(configured["services"]["ntp"]["defined_key_ids"], ["99"])
        self.assertNotIn("DUMMY", str(configured))

    def test_broader_antispoof_denies_cover_required_networks(self):
        # Un refus total bloque toutes les sources usurpées, même si le WAN
        # devient inutilisable (ce qui relève d'un autre contrôle).
        ir = ir_of("""ip access-list extended WAN
 deny ip any any
interface GigabitEthernet0/0
 ip address 198.51.100.2 255.255.255.252
 ip access-group WAN in""")
        ctx = {"external_interfaces": ["GigabitEthernet0/0"]}
        self.assertEqual(CONTEXT_CHECKS["external_antispoof_acl"](ir, True, ctx)[0], "PASS")
        explicit = ir_of("""ip access-list extended WAN
 deny ip 0.0.0.0 255.255.255.255 any
interface GigabitEthernet0/0
 ip address 198.51.100.2 255.255.255.252
 ip access-group WAN in""")
        self.assertEqual(CONTEXT_CHECKS["external_antispoof_acl"](explicit, True, ctx)[0], "PASS")


if __name__ == "__main__":
    unittest.main()
