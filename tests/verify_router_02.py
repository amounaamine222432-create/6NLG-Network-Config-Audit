#!/usr/bin/env python3
"""Deuxieme test independant de parsing IOS V6 - sortie terminal uniquement.

Depuis network-config-audit :
  PYTHONPATH=parsers python3 tests/verify_router_02.py data/validation/R-AUDIT-BRANCH-02.cfg
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cisco_parser import parse_cisco_ios


def first(items: list[dict], **fields: object) -> dict:
    return next((item for item in items if all(item.get(key) == value for key, value in fields.items())), {})


def validate(parsed: dict) -> tuple[int, int]:
    results: list[bool] = []

    def check(description: str, passed: bool) -> None:
        results.append(bool(passed))
        label = "PASS" if passed else "FAIL"
        print(f"[{label}] {description}")

    g = parsed.get("global_settings", {})
    interfaces = parsed.get("interfaces", [])
    by_interface = {i.get("name"): i for i in interfaces}
    loopback = by_interface.get("Loopback0", {})
    lan = by_interface.get("GigabitEthernet0/1", {})
    mgmt = by_interface.get("GigabitEthernet0/3", {})
    dot1q = by_interface.get("GigabitEthernet0/4.100", {})
    helper = by_interface.get("GigabitEthernet0/2", {})

    check("Hostname et version IOS", parsed.get("hostname") == "R-AUDIT-BRANCH-02" and g.get("ios_version") == "15.9")
    check("Commandes CLI enable/configure/end/write reconnues", len(parsed.get("wrapper_commands", [])) == 4)
    vrf = first(parsed.get("vrfs", []), name="ADMIN")
    check("VRF ADMIN definie et appliquee sur interface", vrf.get("rd") == "65120:20" and mgmt.get("vrf_forwarding") == "ADMIN")
    check("7 interfaces extraites, sans doublon", len(interfaces) == 7 and len(by_interface) == 7)
    check("Adresse loopback /32", any(x.get("address") == "10.20.20.20" and x.get("mask") == "255.255.255.255" for x in loopback.get("ipv4_addresses", [])))
    check("Interface de gestion shutdown conservee", mgmt.get("administrative_command") == "shutdown")
    check("Sous-interface 802.1Q VLAN 100", dot1q.get("dot1q") == {"vlan_id": "100", "native": False})
    check("VLAN 100 / nom STAFF", first(parsed.get("vlans", []), name="100").get("configured_name") == "STAFF")

    ospf = first(parsed.get("ospf_processes", []), process_id="20")
    check("OSPF : router-id, 2 reseaux et 2 interfaces passives", ospf.get("router_id") == "10.20.20.20" and len(ospf.get("networks", [])) == 2 and len(ospf.get("passive_interfaces", [])) == 2)
    check("OSPF : redistribution des routes connectees", "redistribute connected subnets" in ospf.get("redistribution_commands", []))

    bgp = first(parsed.get("bgp_processes", []), local_as="65120")
    group = first(bgp.get("neighbors", []), id="UPSTREAM")
    neighbor = first(bgp.get("neighbors", []), id="10.20.0.2")
    check("BGP : AS 65120 / router-id / peer-group UPSTREAM", bgp.get("router_id") == "10.20.20.20" and group.get("is_peer_group") is True and group.get("remote_as") == "65200")
    check("BGP : voisin eBGP et remote-as herite", neighbor.get("peer_group") == "UPSTREAM" and neighbor.get("effective_remote_as") == "65200" and neighbor.get("session_type_configured") == "ebgp")
    check("BGP : address-family IPv4 et annonce network", neighbor.get("activated_families") == ["ipv4"] and any(s.get("prefix") == "172.20.10.0" for s in bgp.get("network_statements", [])))
    check("BGP : politique entrante sur peer-group", any(r.get("name") == "RM_IN" and r.get("direction") == "in" and r.get("address_family") == "ipv4" for r in group.get("route_maps", [])))

    routes = parsed.get("static_routes", [])
    check("Routage statique : 3 routes et route flottante AD 210", len(routes) == 3 and any(r.get("administrative_distance_configured") == 210 for r in routes))
    check("Routage statique : route VRF ADMIN AD 150", any(r.get("vrf") == "ADMIN" and r.get("administrative_distance_configured") == 150 and r.get("next_hop") == "192.0.2.1" for r in routes))

    acl = first(parsed.get("access_lists", []), name="MGMT_SSH")
    acl_rule = acl.get("entries", [{}])[0]
    check("ACL : 2 ACL, regle TCP destination 22", len(parsed.get("access_lists", [])) == 2 and acl_rule.get("action") == "permit" and acl_rule.get("protocol") == "tcp" and acl_rule.get("destination_port") == {"operator": "eq", "ports": ["22"]})
    prefix = first(parsed.get("prefix_lists", []), name="PL_IN")
    rm = first(parsed.get("route_maps", []), name="RM_IN")
    entry = rm.get("entries", [{}])[0]
    check("Prefix-list : 2 entrees permit/deny", len(prefix.get("entries", [])) == 2 and [x.get("action") for x in prefix.get("entries", [])] == ["permit", "deny"])
    check("Route-map : match prefix-list + set local-preference", "match ip address prefix-list PL_IN" in entry.get("match_commands", []) and "set local-preference 180" in entry.get("set_commands", []))
    check("Community-list BGP analysee", first(parsed.get("community_lists", []), name="COMMUNITY_ALLOWED").get("community_type") == "expanded")

    nat = parsed.get("nat_rules", [])
    pool = first(parsed.get("nat_pools", []), name="WAN_POOL")
    check("NAT/PAT : pool WAN_POOL et surcharge overload", len(nat) == 2 and len(pool) > 0 and any(n.get("kind") == "list_pool" and n.get("pool") == "WAN_POOL" and n.get("overload") is True for n in nat))
    check("NAT statique : redirection TCP 443 vers 8443", any(n.get("kind") == "static_port" and n.get("inside_port") == "443" and n.get("outside_port") == "8443" for n in nat))
    check("NAT : roles inside/outside sur les interfaces", lan.get("nat_role") == "inside" and by_interface.get("GigabitEthernet0/0", {}).get("nat_role") == "outside")

    pool_dhcp = first(parsed.get("dhcp_pools", []), name="STAFF_LAN")
    check("DHCP serveur : pool, gateway, DNS et exclusion", pool_dhcp.get("network", {}).get("address") == "172.20.10.0" and pool_dhcp.get("default_routers") == ["172.20.10.1"] and len(pool_dhcp.get("dns_servers", [])) == 2 and len(parsed.get("dhcp_excluded_addresses", [])) == 1)
    check("DHCP relay : ip helper-address", helper.get("ip_helper_addresses") == ["192.0.2.53"])

    hsrp = lan.get("hsrp_groups", [])
    group_hsrp = first(hsrp, group_id="10")
    check("HSRP : version 2, VIP 172.20.10.1, priorite 120, preempt", lan.get("hsrp_version") == "2" and group_hsrp.get("virtual_ip") == "172.20.10.1" and group_hsrp.get("priority") == "120" and group_hsrp.get("preempt") is True)

    snmp = parsed.get("snmp", {})
    syslog = parsed.get("syslog", {})
    check("SNMP : communaute RO et destinataire 2c", len(snmp.get("communities", [])) == 1 and snmp["communities"][0].get("access") == "RO" and len(snmp.get("hosts", [])) == 1 and snmp["hosts"][0].get("version") == "2c")
    check("Syslog : destination, source et niveau warnings", len(syslog.get("hosts", [])) == 1 and syslog.get("source_interface") == "Loopback0" and syslog.get("trap_level") == "warnings")

    lines = first(parsed.get("lines", []), identifier="vty 0 4")
    check("Acces VTY : SSH uniquement, login local", lines.get("transport_input") == ["ssh"] and lines.get("login_method") == "local" and lines.get("exec_timeout") == ["5", "0"])
    check("Administration : HTTP desactive, HTTPS active, SSHv2", g.get("http_server_enabled") is False and g.get("https_server_enabled") is True and "ip ssh version 2" in g.get("ssh_commands", []))
    check("Compte utilisateur sans export du faux hash", len(parsed.get("local_users", [])) == 1 and "FAKE_HASH_FOR_PARSER_TEST_ONLY" not in json.dumps(parsed))
    check("Banniere MOTD reconnue", len(parsed.get("banners", [])) == 1 and parsed["banners"][0].get("kind") == "motd")
    check("Aucune ligne globale silencieusement ignoree", len(parsed.get("unparsed_lines", [])) == 0)

    passed = sum(results)
    print("\n" + "=" * 68)
    print(f"VALIDATION INDEPENDANTE N°2 : {passed}/{len(results)} CONTROLES REUSSIS")
    print("=" * 68)
    print("Portee : extraction statique des champs testes ; pas de validation de l'etat du reseau.")
    return passed, len(results)


def main() -> int:
    cli = argparse.ArgumentParser(description="Validation terminal uniquement du routeur IOS fictif n°2")
    cli.add_argument("config", nargs="?", type=Path, default=Path("data/validation/R-AUDIT-BRANCH-02.cfg"))
    args = cli.parse_args()
    if not args.config.is_file():
        cli.error(f"Configuration introuvable : {args.config}")
    parsed = parse_cisco_ios(args.config.read_text(encoding="utf-8-sig"))
    passed, total = validate(parsed)
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
