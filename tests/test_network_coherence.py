import unittest

from audit_engine.network_coherence import audit_network_coherence


class NetworkCoherenceTests(unittest.TestCase):
    def test_shadowing_standard_acl_and_trace(self):
        ir = {"routing": {}, "interfaces": [], "policies": {"acls": [{
            "name": "MGMT", "type": "standard", "entries": [
                {"action": "deny", "source_match": {"kind": "any"}, "source": {"line": 7}},
                {"action": "permit", "source_match": {"kind": "host", "address": "10.0.0.1"}, "source": {"line": 8}},
            ]}]}}
        findings = audit_network_coherence(ir)["findings"]
        shadow = next(f for f in findings if f["rule_id"] == "ACL_RULE_SHADOWING")
        self.assertEqual(shadow["status"], "FAIL")
        self.assertEqual(shadow["evidence"]["shadowed_rules"][0]["masking_line"], 7)

    def test_unknown_acl_syntax_is_not_assumed_shadowed(self):
        ir = {"routing": {}, "interfaces": [], "policies": {"acls": [{
            "name": "X", "type": "extended", "entries": [
                {"action": "permit", "protocol": "tcp", "source_match": {"kind": "any"},
                 "destination_match": {"kind": "any"}, "destination_port": {"operator": "eq", "value": "443"}},
                {"action": "permit", "protocol": "tcp", "source_match": {"kind": "host", "address": "10.0.0.1"},
                 "destination_match": {"kind": "any"}},
            ]}]}}
        shadow = next(f for f in audit_network_coherence(ir)["findings"]
                      if f["rule_id"] == "ACL_RULE_SHADOWING")
        self.assertEqual(shadow["status"], "UNKNOWN")

    def test_directly_connected_default_route(self):
        ir = {"routing": {"static_routes": [{"prefix": "0.0.0.0/0", "next_hop": "192.0.2.1"}]},
              "interfaces": [{"name": "Gi0/0", "ipv4_addresses": [{"cidr": "192.0.2.2/30"}]}],
              "policies": {"acls": []}}
        gateway = next(f for f in audit_network_coherence(ir)["findings"]
                       if f["rule_id"] == "INVALID_DEFAULT_GATEWAY")
        self.assertEqual(gateway["status"], "PASS")

    def test_missing_gateway_is_review_not_false_failure(self):
        ir = {"routing": {"static_routes": [{"prefix": "0.0.0.0/0", "next_hop": "192.0.2.1"}]},
              "interfaces": [], "policies": {"acls": []}}
        gateway = next(f for f in audit_network_coherence(ir)["findings"]
                       if f["rule_id"] == "INVALID_DEFAULT_GATEWAY")
        self.assertEqual(gateway["status"], "REVIEW")

    def test_vty_acl_binding_is_not_unused(self):
        ir = {"routing": {}, "interfaces": [],
              "management": {"terminal_lines": [{"line_id": "vty 0 4",
                            "access_classes": [{"acl": "MGMT-VTY", "direction": "in"}]}]},
              "policies": {"acls": [{"name": "MGMT-VTY", "type": "standard", "entries": []}]}}
        unused = next(f for f in audit_network_coherence(ir)["findings"]
                      if f["rule_id"] == "UNUSED_ACL")
        self.assertEqual(unused["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
