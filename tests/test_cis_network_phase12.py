"""Conservative network-coherence regression cases for phase 1+2."""

import unittest

from audit_engine.network_coherence import audit_network_coherence


def finding(ir, code, complete=False):
    return next(item for item in audit_network_coherence(ir, complete_config=complete)["findings"]
                if item["rule_id"] == code)


class CoherencePhase12Tests(unittest.TestCase):
    def test_overlap_same_vrf_is_review_with_lines(self):
        ir = {"interfaces": [
            {"name": "Gi0/0", "vrf": "RED", "source": {"line": 12},
             "ipv4_addresses": [{"cidr": "10.10.0.1/24"}]},
            {"name": "Gi0/1", "vrf": "RED", "source": {"line": 19},
             "ipv4_addresses": [{"cidr": "10.10.0.2/25"}]}]}
        result = finding(ir, "OVERLAPPING_INTERFACE_SUBNETS")
        self.assertEqual(result["status"], "REVIEW")
        self.assertEqual(result["evidence"]["overlaps"][0]["source_lines"], [12, 19])

    def test_overlap_different_vrf_is_not_a_conflict(self):
        ir = {"interfaces": [
            {"name": "Gi0/0", "vrf": "RED", "ipv4_addresses": [{"cidr": "10.10.0.1/24"}]},
            {"name": "Gi0/1", "vrf": "BLUE", "ipv4_addresses": [{"cidr": "10.10.0.2/24"}]}]}
        self.assertEqual(finding(ir, "OVERLAPPING_INTERFACE_SUBNETS")["status"], "PASS")

    def test_undefined_acl_requires_explicit_completeness_for_fail(self):
        ir = {"interfaces": [{"name": "Gi0/0", "source": {"line": 4},
                              "acl_bindings": [{"name": "WAN-FILTER", "direction": "in"}]}],
              "policies": {"acls": []}}
        self.assertEqual(finding(ir, "UNDEFINED_ACL_BINDING")["status"], "REVIEW")
        self.assertEqual(finding(ir, "UNDEFINED_ACL_BINDING", True)["status"], "FAIL")

    def test_defined_acl_is_not_missing(self):
        ir = {"interfaces": [{"acl_bindings": [{"name": "WAN-FILTER"}]}],
              "policies": {"acls": [{"name": "WAN-FILTER"}]}}
        self.assertEqual(finding(ir, "UNDEFINED_ACL_BINDING", True)["status"], "PASS")

    def test_dhcp_overlap_and_absent_not_applicable(self):
        ir = {"services": {"dhcp": {"pools": [{"name": "A", "subnet": "192.0.2.0/24"},
                                                 {"name": "B", "subnet": "192.0.2.0/25"}]}}}
        self.assertEqual(finding(ir, "OVERLAPPING_DHCP_POOLS")["status"], "REVIEW")
        self.assertEqual(finding({}, "OVERLAPPING_DHCP_POOLS")["status"], "NOT_APPLICABLE")


if __name__ == "__main__":
    unittest.main()
