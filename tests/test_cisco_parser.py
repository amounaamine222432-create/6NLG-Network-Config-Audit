"""Tests built only with Python's standard library (unittest)."""

import json
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from cisco_parser import main, parse_cisco_ios


class ParserTests(unittest.TestCase):
    def test_full_c4geeks_static_cli(self):
        config = """\
! Example of a CLI script
enable
configure terminal
hostname R1
interface Loopback1
 ip address 192.168.1.1 255.255.255.0
 exit
interface GigabitEthernet0/0
 ip address 10.0.12.1 255.255.255.252
 no shutdown
 exit
interface GigabitEthernet1/0
 ip address 10.0.13.1 255.255.255.252
 no shutdown
 exit
ip route 192.168.2.0 255.255.255.0 10.0.12.2
ip route 192.168.2.0 255.255.255.0 10.0.13.2 200
ip route 0.0.0.0 0.0.0.0 10.0.12.2
end
write memory
"""
        parsed = parse_cisco_ios(config)
        self.assertEqual(parsed["hostname"], "R1")
        self.assertEqual(len(parsed["interfaces"]), 3)
        self.assertEqual(len(parsed["static_routes"]), 3)
        self.assertEqual(parsed["static_routes"][1]["administrative_distance_configured"], 200)
        self.assertEqual(parsed["static_routes"][0]["administrative_distance_configured"], None)
        self.assertEqual(parsed["static_routes"][1]["next_hop"], "10.0.13.2")
        self.assertFalse(parsed["unparsed_lines"])
        self.assertEqual(len(parsed["wrapper_commands"]), 7)

    def test_bgp_peer_groups_address_family_policy(self):
        parsed = parse_cisco_ios("""\
hostname border
router bgp 65001
 bgp router-id 1.1.1.1
 neighbor ISP peer-group
 neighbor ISP remote-as 65002
 neighbor 10.0.0.2 peer-group ISP
 !
 address-family ipv4
  network 203.0.113.0 mask 255.255.255.0
  neighbor ISP route-map FILTER_IN in
  neighbor 10.0.0.2 activate
 exit-address-family
!
route-map FILTER_IN permit 10
 match ip address prefix-list PL
 set local-preference 200
!\n""")
        bgp = parsed["bgp_processes"][0]
        self.assertEqual(bgp["local_as"], "65001")
        self.assertEqual(bgp["router_id"], "1.1.1.1")
        self.assertEqual(bgp["network_statements"][0]["prefix"], "203.0.113.0")
        self.assertEqual(bgp["network_statements"][0]["address_family"], "ipv4")
        n = next(x for x in bgp["neighbors"] if x["id"] == "10.0.0.2")
        self.assertEqual(n["peer_group"], "ISP")
        self.assertEqual(n["activated_families"], ["ipv4"])
        group = next(x for x in bgp["neighbors"] if x["id"] == "ISP")
        self.assertTrue(group["is_peer_group"])
        self.assertEqual(group["remote_as"], "65002")
        self.assertEqual(group["route_maps"][0]["direction"], "in")
        self.assertEqual(parsed["route_maps"][0]["entries"][0]["set_commands"], ["set local-preference 200"])

    def test_access_lists_prefix_lists_and_community(self):
        parsed = parse_cisco_ios("""\
ip access-list extended BLOCK_TELNET
 10 deny tcp any any eq 23
 20 permit ip any any
 exit
access-list 101 permit ip any any
ip prefix-list LIMIT seq 10 deny 10.0.0.0/8 le 32
ip prefix-list LIMIT seq 20 permit 0.0.0.0/0 le 32
ip community-list expanded ACCEPT permit _65000:
""")
        self.assertEqual(len(parsed["access_lists"]), 2)
        named = next(x for x in parsed["access_lists"] if x["name"] == "BLOCK_TELNET")
        self.assertEqual(named["acl_type"], "extended")
        self.assertEqual(named["entries"][0]["sequence"], "10")
        self.assertEqual(named["entries"][0]["action"], "deny")
        self.assertEqual(len(parsed["prefix_lists"][0]["entries"]), 2)
        self.assertEqual(parsed["prefix_lists"][0]["entries"][0]["le"], "32")
        self.assertEqual(parsed["community_lists"][0]["name"], "ACCEPT")

    def test_ospf_and_interfaces(self):
        parsed = parse_cisco_ios("""\
hostname R3
interface Loopback0
 ip address 10.10.10.10 255.255.255.255
!\ninterface Ethernet0/0
 no ip address
 shutdown
!\nrouter ospf 1
 router-id 10.10.10.10
 network 10.0.0.0 0.255.255.255 area 0
 passive-interface Loopback0
 redistribute connected subnets
!\n""")
        self.assertEqual(len(parsed["interfaces"]), 2)
        self.assertEqual(parsed["interfaces"][1]["administrative_command"], "shutdown")
        ospf = parsed["ospf_processes"][0]
        self.assertEqual(ospf["networks"][0]["area"], "0")
        self.assertEqual(ospf["passive_interfaces"], ["Loopback0"])

    def test_vrf_interface_static_and_invalid_static(self):
        parsed = parse_cisco_ios("""\
ip route vrf MGMT 10.20.0.0 255.255.0.0 GigabitEthernet0/0 10.0.0.1 150 track 1
ip route foo bad address
""")
        self.assertEqual(len(parsed["static_routes"]), 1)
        route = parsed["static_routes"][0]
        self.assertEqual(route["vrf"], "MGMT")
        self.assertEqual(route["outgoing_interface"], "GigabitEthernet0/0")
        self.assertEqual(route["next_hop"], "10.0.0.1")
        self.assertEqual(route["administrative_distance_configured"], 150)
        self.assertEqual(len(parsed["unparsed_lines"]), 1)

    def test_no_silent_loss_unknown_commands(self):
        parsed = parse_cisco_ios("""\
service timestamps log datetime msec
unexpected-global-flag enabled
interface Ethernet0/0
 custom-interface-flag enabled
!\nrouter bgp 65000
 unsupported-bgp-directive test
!\n""")
        self.assertEqual(parsed["global_settings"]["service_timestamps"],
                         ["service timestamps log datetime msec"])
        self.assertEqual(parsed["unparsed_lines"][0]["line"], 2)
        self.assertEqual(parsed["interfaces"][0]["other_commands"], ["custom-interface-flag enabled"])
        self.assertIn("unsupported-bgp-directive test", parsed["bgp_processes"][0]["other_commands"])

    def test_export_batch_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "input"
            target = Path(tmp) / "output"
            nested = source / "ospf"
            nested.mkdir(parents=True)
            (nested / "R1-config.txt").write_text("hostname R1\nrouter ospf 1\n router-id 1.1.1.1\n")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(source), "--output-dir", str(target)]), 0)
            output = json.loads((target / "ospf" / "R1-config.json").read_text())
            self.assertEqual(output["hostname"], "R1")

    def test_nat_pat_c4geeks(self):
        parsed = parse_cisco_ios("""\
enable
configure terminal
hostname R1
interface GigabitEthernet0/0
 ip nat inside
 exit
interface GigabitEthernet1/0
 ip nat outside
 exit
ip nat inside source static 192.168.20.20 203.0.113.10
access-list 1 permit 192.168.10.0 0.0.0.255
ip nat pool PUBLIC 203.0.113.9 203.0.113.9 prefix-length 29
ip nat inside source list 1 pool PUBLIC overload
end
""")
        self.assertEqual([i["nat_role"] for i in parsed["interfaces"]], ["inside", "outside"])
        self.assertEqual(len(parsed["nat_rules"]), 2)
        self.assertEqual(parsed["nat_rules"][0]["kind"], "static")
        self.assertTrue(parsed["nat_rules"][1]["overload"])
        self.assertEqual(parsed["nat_rules"][1]["pool"], "PUBLIC")
        self.assertEqual(parsed["nat_pools"][0]["name"], "PUBLIC")
        self.assertEqual(parsed["access_lists"][0]["entries"][0]["source"]["wildcard"], "0.0.0.255")

    def test_static_nat_port(self):
        parsed = parse_cisco_ios("ip nat inside source static tcp 192.168.1.2 443 203.0.113.5 8443\n")
        rule = parsed["nat_rules"][0]
        self.assertEqual(rule["kind"], "static_port")
        self.assertEqual(rule["protocol"], "tcp")
        self.assertEqual(rule["inside_port"], "443")
        self.assertEqual(rule["outside_port"], "8443")

    def test_hsrp_vlan_dot1q_and_trunk(self):
        parsed = parse_cisco_ios("""\
interface GigabitEthernet0/0
 standby version 2
 standby 1 ip 192.168.10.254
 standby 1 priority 110
 standby 1 preempt
!\ninterface GigabitEthernet0/0.10
 encapsulation dot1Q 10 native
!\ninterface GigabitEthernet1/0
 switchport mode trunk
 switchport trunk native vlan 99
 switchport trunk allowed vlan 10,20,99
!\nvlan 10
 name USERS
!\n""")
        i = parsed["interfaces"]
        self.assertEqual(i[0]["hsrp_version"], "2")
        self.assertEqual(i[0]["hsrp_groups"][0]["virtual_ip"], "192.168.10.254")
        self.assertEqual(i[0]["hsrp_groups"][0]["priority"], "110")
        self.assertTrue(i[0]["hsrp_groups"][0]["preempt"])
        self.assertEqual(i[1]["dot1q"], {"vlan_id": "10", "native": True})
        self.assertEqual(i[2]["switchport"]["mode"], "trunk")
        self.assertEqual(i[2]["switchport"]["native_vlan"], "99")
        self.assertEqual(parsed["vlans"][0]["configured_name"], "USERS")

    def test_dhcp_pool_and_relay(self):
        parsed = parse_cisco_ios("""\
ip dhcp excluded-address 192.168.10.1 192.168.10.20
ip dhcp pool LAN
 network 192.168.10.0 255.255.255.0
 default-router 192.168.10.1
 dns-server 1.1.1.1 8.8.8.8
 domain-name example.local
!\ninterface GigabitEthernet0/0
 ip helper-address 192.0.2.53
!\n""")
        self.assertEqual(parsed["dhcp_excluded_addresses"][0]["addresses"],
                         ["192.168.10.1", "192.168.10.20"])
        pool = parsed["dhcp_pools"][0]
        self.assertEqual(pool["default_routers"], ["192.168.10.1"])
        self.assertEqual(pool["dns_servers"], ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(parsed["interfaces"][0]["ip_helper_addresses"], ["192.0.2.53"])

    def test_snmp_and_syslog(self):
        parsed = parse_cisco_ios("""\
snmp-server community public RO 10
snmp-server host 192.0.2.10 version 2c public
snmp-server enable traps
logging host 192.0.2.11
logging 192.0.2.12
logging source-interface Loopback0
logging trap warnings
""")
        self.assertEqual(parsed["snmp"]["communities"][0]["access"], "RO")
        self.assertEqual(parsed["snmp"]["hosts"][0]["host"], "192.0.2.10")
        self.assertEqual(parsed["snmp"]["hosts"][0]["version"], "2c")
        self.assertEqual(len(parsed["syslog"]["hosts"]), 2)
        self.assertEqual(parsed["syslog"]["source_interface"], "Loopback0")
        self.assertEqual(parsed["syslog"]["trap_level"], "warnings")

    def test_extended_acl_structured_fields(self):
        parsed = parse_cisco_ios("""\
ip access-list extended BLOCK_TELNET
 10 deny tcp any any eq 23
 20 permit ip 192.0.2.0 0.0.0.255 any
 exit
""")
        first, second = parsed["access_lists"][0]["entries"]
        self.assertEqual(first["protocol"], "tcp")
        self.assertEqual(first["source"], {"kind": "any"})
        self.assertEqual(first["destination_port"], {"operator": "eq", "ports": ["23"]})
        self.assertEqual(second["source"]["wildcard"], "0.0.0.255")

    def test_bgp_peer_group_remote_as_inheritance(self):
        parsed = parse_cisco_ios("""\
router bgp 65000
 neighbor UPSTREAM peer-group
 neighbor UPSTREAM remote-as 65100
 neighbor 192.0.2.2 peer-group UPSTREAM
 neighbor 192.0.2.3 remote-as 65000
!\n""")
        bgp = parsed["bgp_processes"][0]
        external = next(n for n in bgp["neighbors"] if n["id"] == "192.0.2.2")
        internal = next(n for n in bgp["neighbors"] if n["id"] == "192.0.2.3")
        self.assertEqual(external["effective_remote_as"], "65100")
        self.assertEqual(external["remote_as_inherited_from"], "UPSTREAM")
        self.assertEqual(external["session_type_configured"], "ebgp")
        self.assertEqual(internal["session_type_configured"], "ibgp")


if __name__ == "__main__":
    unittest.main(verbosity=2)
