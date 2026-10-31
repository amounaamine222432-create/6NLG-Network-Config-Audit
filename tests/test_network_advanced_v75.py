"""V75 OSPF/BGP/VLAN/NAT evidence and conservative decision tests."""
import unittest

from audit_engine.network_coherence import audit_network_coherence


def rule(ir, code, complete=True):
    return next(f for f in audit_network_coherence(ir, complete_config=complete)["findings"]
                if f["rule_id"] == code)


class AdvancedCoherenceV75(unittest.TestCase):
    def test_ospf_md5_missing_key_is_review_not_fail(self):
        ir = {"routing": {"ospf": [{"process_id": "10"}]},
              "interfaces": [{"name": "Gi0/1", "source": {"line": 22},
                              "ospf_authentication_mode": "message-digest", "ospf_md5_key_ids": []}]}
        f = rule(ir, "OSPF_MD5_KEY_COHERENCE")
        self.assertEqual(f["status"], "REVIEW")
        self.assertEqual(f["evidence"]["candidates"][0]["source_line"], 22)
        ir["interfaces"][0]["ospf_md5_key_ids"] = ["1"]
        self.assertEqual(rule(ir, "OSPF_MD5_KEY_COHERENCE")["status"], "PASS")

    def test_bgp_as_and_remote_neighbor_are_distinct(self):
        ir = {"routing": {"bgp": [{"neighbors": [
            {"id": "192.0.2.55", "remote_as": 65055, "source": {"line": 49}}]}]},
            "interfaces": [{"ipv4_addresses": [{"cidr": "198.51.100.2/30"}]}]}
        self.assertEqual(rule(ir, "BGP_REMOTE_AS_COHERENCE")["status"], "PASS")
        self.assertEqual(rule(ir, "BGP_PEER_REACHABILITY")["status"], "REVIEW")
        ir["routing"]["bgp"][0]["neighbors"][0]["remote_as"] = 4294967296
        self.assertEqual(rule(ir, "BGP_REMOTE_AS_COHERENCE")["status"], "FAIL")

    def test_undeclared_vlan_requires_complete_local_inventory(self):
        ir = {"services": {"vlans": [{"id": 100}]},
              "interfaces": [{"name": "Gi0/2", "source": {"line": 9},
                              "switchport": {"mode": "access", "access_vlan": 999}}]}
        self.assertEqual(rule(ir, "UNDECLARED_ACCESS_VLAN")["status"], "FAIL")
        self.assertEqual(rule(ir, "UNDECLARED_ACCESS_VLAN", False)["status"], "REVIEW")
        self.assertEqual(rule({"interfaces": ir["interfaces"]}, "UNDECLARED_ACCESS_VLAN")["status"], "REVIEW")

    def test_static_nat_collision_but_pat_ports_allowed(self):
        ir = {"services": {"nat": {"rules": [
            {"inside_local": "10.0.0.10", "inside_global": "203.0.113.10", "source": {"line": 7}},
            {"inside_local": "10.0.0.11", "inside_global": "203.0.113.10", "source": {"line": 8}}]}}}
        f = rule(ir, "NAT_STATIC_GLOBAL_COLLISION")
        self.assertEqual(f["status"], "FAIL")
        self.assertEqual(f["evidence"]["collisions"][0]["source_lines"], [7, 8])
        ir["services"]["nat"]["rules"][0].update({"protocol": "tcp", "outside_port": 80})
        ir["services"]["nat"]["rules"][1].update({"protocol": "tcp", "outside_port": 443})
        self.assertEqual(rule(ir, "NAT_STATIC_GLOBAL_COLLISION")["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
