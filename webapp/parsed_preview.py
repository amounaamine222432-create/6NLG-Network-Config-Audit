"""Vue JSON expurgée du parsing Cisco IOS, destinée au navigateur.

Contrairement à l'IR, cette vue conserve les noms de champs proches de la
syntaxe IOS (masques, processus, sous-commandes). Seuls les champs de la
liste blanche sont exportés : jamais `raw`, `password`, `community`,
`global_commands`, `other_commands` ou le texte CLI original.
"""

from __future__ import annotations

from typing import Any


def _pick(source: Any, *fields: str) -> dict:
    if not isinstance(source, dict):
        return {}
    return {field: source[field] for field in fields if field in source}


def _sequence(value: Any) -> list:
    return value if isinstance(value, list) else []


def safe_parsed_preview(parsed: dict, filename: str) -> dict:
    """Conserver des informations de parsing utiles, sans exporter de secrets."""
    interfaces = []
    for item in _sequence(parsed.get("interfaces")):
        interfaces.append({
            **_pick(item, "name", "description", "source_line", "administrative_command",
                    "vrf_forwarding", "nat_role", "ospf_network_type", "ipv4_dhcp"),
            "ipv4_addresses": [_pick(addr, "address", "mask") for addr in _sequence(item.get("ipv4_addresses"))],
            "acl_bindings": [_pick(acl, "name", "direction") for acl in _sequence(item.get("acl_bindings"))],
            "dot1q": _pick(item.get("dot1q"), "vlan_id", "native"),
            "switchport": _pick(item.get("switchport"), "mode", "access_vlan", "native_vlan", "trunk_encapsulation"),
            "dhcp_relay_addresses": list(_sequence(item.get("ip_helper_addresses"))),
            "hsrp_groups": [_pick(group, "group_id", "virtual_ip", "priority", "preempt")
                            for group in _sequence(item.get("hsrp_groups"))],
            "other_command_count": len(_sequence(item.get("other_commands"))),
        })

    ospf = []
    for item in _sequence(parsed.get("ospf_processes")):
        ospf.append({
            **_pick(item, "process_id", "router_id", "source_line", "default_information_originate"),
            "networks": [_pick(net, "network", "wildcard_mask", "area") for net in _sequence(item.get("networks"))],
            "passive_interfaces": list(_sequence(item.get("passive_interfaces"))),
            "non_passive_interfaces": list(_sequence(item.get("non_passive_interfaces"))),
            "redistribution_command_count": len(_sequence(item.get("redistribution_commands"))),
            "other_command_count": len(_sequence(item.get("other_commands"))),
        })

    bgp = []
    for item in _sequence(parsed.get("bgp_processes")):
        peers = []
        for peer in _sequence(item.get("neighbors")):
            peers.append({
                **_pick(peer, "id", "remote_as", "effective_remote_as", "peer_group", "is_peer_group",
                        "session_type_configured", "update_source", "source_line"),
                "route_maps": [_pick(policy, "name", "direction", "address_family")
                               for policy in _sequence(peer.get("route_maps"))],
                "description_configured": bool(peer.get("description_configured")),
                "password_redacted": bool(peer.get("password_configured")),
            })
        bgp.append({
            **_pick(item, "local_as", "router_id", "source_line"),
            "neighbors": peers,
            "network_statements": [_pick(net, "prefix", "mask", "address_family")
                                   for net in _sequence(item.get("network_statements"))],
            "address_families": [_pick(family, "name") for family in _sequence(item.get("address_families"))],
            "other_command_count": len(_sequence(item.get("other_commands"))),
        })

    acls = []
    for acl in _sequence(parsed.get("access_lists")):
        acls.append({
            **_pick(acl, "name", "acl_type"),
            "entries": [{
                **_pick(entry, "action", "protocol", "sequence", "source_line"),
                "source": _pick(entry.get("source"), "kind", "address", "wildcard", "name"),
                "destination": _pick(entry.get("destination"), "kind", "address", "wildcard", "name"),
                "source_port": _pick(entry.get("source_port"), "operator", "ports"),
                "destination_port": _pick(entry.get("destination_port"), "operator", "ports"),
            } for entry in _sequence(acl.get("entries"))],
            "other_command_count": len(_sequence(acl.get("other_commands"))),
        })

    nat = [_pick(item, "kind", "acl", "pool", "interface", "overload", "inside_local",
                 "inside_global", "protocol", "inside_port", "outside_port", "source_line")
           for item in _sequence(parsed.get("nat_rules"))]

    dhcp = []
    for pool in _sequence(parsed.get("dhcp_pools")):
        dhcp.append({
            **_pick(pool, "name", "network", "default_routers", "dns_servers", "domain_name"),
            "lease": _pick(pool.get("lease"), "infinite", "duration_seconds"),
            "other_command_count": len(_sequence(pool.get("other_commands"))),
        })

    snmp = parsed.get("snmp") or {}
    syslog = parsed.get("syslog") or {}
    ntp = parsed.get("ntp") or {}
    g = parsed.get("global_settings") or {}

    return {
        "file": filename,
        "vendor": parsed.get("vendor"),
        "hostname": parsed.get("hostname"),
        "global_settings": {
            **_pick(g, "ios_version", "http_server_enabled", "https_server_enabled",
                    "ip_domain_lookup_enabled", "ip_cef_enabled", "ipv6_cef_enabled",
                    "spanning_tree_mode", "cdp_enabled", "ip_source_route_enabled",
                    "enable_secret_configured", "enable_password_configured"),
            "ssh_v2_declared": "ip ssh version 2" in _sequence(g.get("ssh_commands")),
        },
        "interfaces": interfaces,
        "static_routes": [_pick(route, "destination", "mask", "vrf", "next_hop", "outgoing_interface", "source_line")
                          for route in _sequence(parsed.get("static_routes"))],
        "ospf_processes": ospf,
        "bgp_processes": bgp,
        "access_lists": acls,
        "prefix_lists": [{
            "name": item.get("name"),
            "entries": [_pick(entry, "sequence", "action", "prefix", "ge", "le", "source_line")
                        for entry in _sequence(item.get("entries"))],
        } for item in _sequence(parsed.get("prefix_lists"))],
        "route_maps": [{
            "name": item.get("name"),
            "entries": [{
                **_pick(entry, "action", "sequence", "source_line"),
                "match_command_count": len(_sequence(entry.get("match_commands"))),
                "set_command_count": len(_sequence(entry.get("set_commands"))),
                "other_command_count": len(_sequence(entry.get("other_commands"))),
            } for entry in _sequence(item.get("entries"))],
        } for item in _sequence(parsed.get("route_maps"))],
        "vrfs": [_pick(item, "name", "rd", "description", "address_families")
                 for item in _sequence(parsed.get("vrfs"))],
        "vlans": [_pick(item, "name", "configured_name") for item in _sequence(parsed.get("vlans"))],
        "dhcp_pools": dhcp,
        "dhcp_excluded_addresses": [_pick(item, "addresses", "source_line")
                                    for item in _sequence(parsed.get("dhcp_excluded_addresses"))],
        "nat_rules": nat,
        "nat_pools": [_pick(item, "name", "start_address", "end_address", "netmask", "prefix_length")
                      for item in _sequence(parsed.get("nat_pools"))],
        "snmp": {
            "communities": [{"access": item.get("access"), "secret_redacted": True}
                            for item in _sequence(snmp.get("communities"))],
            "users": [{"version": item.get("version"), "secrets_redacted": True}
                      for item in _sequence(snmp.get("users"))],
            "groups": [_pick(item, "version", "security_level") for item in _sequence(snmp.get("groups"))],
            "targets": [_pick(item, "host", "version") for item in _sequence(snmp.get("hosts"))],
        },
        "syslog": {
            "hosts": [_pick(item, "host") for item in _sequence(syslog.get("hosts"))],
            "buffered_configured": isinstance(syslog.get("buffered"), dict),
        },
        "ntp": {
            "servers": [_pick(item, "target", "vrf", "prefer") for item in _sequence(ntp.get("servers"))],
            "peers": [_pick(item, "target", "vrf", "prefer") for item in _sequence(ntp.get("peers"))],
            "authentication_enabled": ntp.get("authentication_enabled"),
            "authentication_keys_configured": len(_sequence(ntp.get("authentication_keys"))),
        },
        "management": {
            "terminal_lines": [{
                **_pick(item, "identifier", "transport_input", "login_method", "source_line"),
                "password_redacted": bool(item.get("password_configured")),
            } for item in _sequence(parsed.get("lines"))],
            "local_account_count": len(_sequence(parsed.get("local_users"))),
            "credentials_never_exported": True,
        },
        "diagnostics": {
            "unparsed_global_count": len(_sequence(parsed.get("unparsed_lines"))),
            "unparsed_global_line_numbers": [item.get("line") for item in _sequence(parsed.get("unparsed_lines"))],
            "platform_directive_count": len(_sequence(parsed.get("platform_commands"))),
            "raw_config_retained": False,
        },
    }
