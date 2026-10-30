"""Inventaire public du *parsing* Junos, distinct de la normalisation IR.

Toutes les relations syntaxiques proviennent de l'AST fourni par
ciscoconfparse2 ou clijson. Le module ne reparsse pas la configuration brute.
Les seuls champs exportés sont explicitement autorisés : aucune commande
inconnue, description libre, clé, identité ou mot de passe ne quitte le serveur.
"""

from __future__ import annotations

from collections import Counter
import ipaddress
import re
from typing import Any


_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:/@-]{1,127}\Z")
_INTERFACE = re.compile(r"[A-Za-z][A-Za-z0-9_.:/-]{0,63}\Z")
_SECTIONS = frozenset({
    "interfaces", "protocols", "routing-instances", "routing-options", "policy-options",
    "system", "security", "firewall", "vlans", "switch-options", "forwarding-options",
})
_PROTOCOLS = frozenset({"bgp", "ospf", "isis", "ldp", "rsvp", "mpls", "evpn", "lldp", "stp"})


def _parts(node: Any | None) -> list[str]:
    return node.text.strip().split() if node is not None else []


def _children(node: Any | None, keyword: str | None = None) -> list[Any]:
    children = list(getattr(node, "children", []) or [])
    return children if keyword is None else [
        child for child in children if _parts(child) and _parts(child)[0] == keyword
    ]


def _first(node: Any | None, keyword: str) -> Any | None:
    return next(iter(_children(node, keyword)), None)


def _value(node: Any | None, keyword: str) -> str | None:
    item = _first(node, keyword)
    tokens = _parts(item)
    return tokens[1] if len(tokens) == 2 and not _children(item) else None


def _identifier(value: str | None, *, interface: bool = False) -> str | None:
    if value is None:
        return None
    return value if (_INTERFACE if interface else _IDENTIFIER).fullmatch(value) else None


def _integer(value: str | None, *, low: int = 0, high: int = 4294967295) -> int | None:
    if value is not None and value.isascii() and value.isdecimal():
        number = int(value)
        if low <= number <= high:
            return number
    return None


def _ip_address(value: str | None) -> str | None:
    try:
        return str(ipaddress.ip_address(value)) if value else None
    except ValueError:
        return None


def _ip_interface(value: str | None) -> str | None:
    try:
        return str(ipaddress.ip_interface(value)) if value else None
    except ValueError:
        return None


def _ip_network(value: str | None) -> str | None:
    try:
        return str(ipaddress.ip_network(value, strict=False)) if value else None
    except ValueError:
        return None


def _named(node: Any | None, keyword: str) -> list[tuple[str, Any]]:
    items = []
    for child in _children(node, keyword):
        tokens = _parts(child)
        if len(tokens) == 2 and (name := _identifier(tokens[1])):
            items.append((name, child))
    return items


def _leaves(node: Any | None, keyword: str, *, interface: bool = False) -> list[str]:
    values = []
    for child in _children(node, keyword):
        tokens = _parts(child)
        if len(tokens) == 2 and not _children(child):
            value = _identifier(tokens[1], interface=interface)
            if value is not None:
                values.append(value)
    return values


def _interfaces(section: Any | None) -> list[dict]:
    items: list[dict] = []
    for physical in _children(section):
        tokens = _parts(physical)
        if len(tokens) != 1 or not (name := _identifier(tokens[0], interface=True)):
            continue
        base_disabled = _first(physical, "disable") is not None
        mtu = _integer(_value(physical, "mtu"), low=256, high=65535)
        for unit_name, unit in _named(physical, "unit"):
            if not unit_name.isdecimal():
                continue
            families: dict[str, dict] = {}
            for family in _children(unit, "family"):
                ft = _parts(family)
                if len(ft) != 2:
                    continue
                if ft[1] in {"inet", "inet6"}:
                    addresses = []
                    expected_version = 4 if ft[1] == "inet" else 6
                    for child in _children(family, "address"):
                        addr_parts = _parts(child)
                        if len(addr_parts) == 2 and (address := _ip_interface(addr_parts[1])):
                            if ipaddress.ip_interface(address).version == expected_version:
                                addresses.append(address)
                    families[ft[1]] = {"addresses": addresses,
                                      "dhcp_configured": any(_parts(n) == ["dhcp"] for n in _children(family, "dhcp"))}
                elif ft[1] == "mpls":
                    families["mpls"] = {"configured": True}
                elif ft[1] == "ethernet-switching":
                    mode = _value(family, "interface-mode")
                    members = _leaves(_first(family, "vlan"), "members")
                    families["ethernet-switching"] = {
                        "interface_mode": mode if mode in ("access", "trunk") else None,
                        "vlan_members": members,
                    }
            entry = {
                "name": f"{name}.{unit_name}", "physical_name": name,
                "unit": int(unit_name), "source_line": None,
                "description_configured": bool(_first(physical, "description") or _first(unit, "description")),
                "admin_disabled_configured": base_disabled or _first(unit, "disable") is not None,
                "mtu": mtu, "families": families,
                "ipv4_addresses": families.get("inet", {}).get("addresses", []),
                "ipv6_addresses": families.get("inet6", {}).get("addresses", []),
            }
            items.append(entry)
    return items


def _static_routes(options: Any | None, vrf: str | None = None) -> list[dict]:
    routes = []
    for route in _children(_first(options, "static"), "route"):
        parts = _parts(route)
        if len(parts) < 2 or not (prefix := _ip_network(parts[1])):
            continue
        inline = parts[2:]
        hop = _value(route, "next-hop")
        if hop is None and len(inline) == 2 and inline[0] == "next-hop":
            hop = inline[1]
        action = next((keyword for keyword in ("discard", "reject")
                       if _first(route, keyword) is not None or keyword in inline), None)
        validated_hop = _ip_address(hop) or _identifier(hop, interface=True)
        preference = _integer(_value(route, "preference"), low=0, high=255)
        if not validated_hop and not action:
            continue
        routes.append({"prefix": prefix, "vrf": vrf, "next_hop": validated_hop,
                       "action": action, "junos_preference": preference, "source_line": None})
    return routes


def _routing_instances(section: Any | None, global_options: Any | None) -> tuple[list[dict], list[dict]]:
    instances: list[dict] = []
    routes: list[dict] = []
    for node in _children(section):
        tokens = _parts(node)
        if len(tokens) != 1 or not (name := _identifier(tokens[0])):
            continue
        kind = _value(node, "instance-type")
        vrf_protocols = _first(node, "protocols")
        vrf_options = _first(node, "routing-options")
        entry = {"name": name, "instance_type": kind if kind in (
            "virtual-router", "vrf", "evpn", "vpls", "forwarding", "no-forwarding") else None,
                 "interfaces": _leaves(node, "interface", interface=True),
                 "route_distinguisher": _identifier(_value(node, "route-distinguisher")),
                 "vrf_target": _identifier(_value(node, "vrf-target")),
                 "protocols_present": sorted(p for p in _PROTOCOLS if _first(vrf_protocols, p) is not None),
                 "ospf_processes": _ospf(vrf_protocols),
                 "bgp_processes": _bgp(vrf_protocols, vrf_options or global_options),
                 "source_line": None}
        instances.append(entry)
        routes.extend(_static_routes(vrf_options, vrf=name))
    return instances, routes


def _ospf(protos: Any | None) -> list[dict]:
    ospf = _first(protos, "ospf")
    if ospf is None:
        return []
    areas = []
    for area_name, area in _named(ospf, "area"):
        interfaces = []
        for interface_name, item in _named(area, "interface"):
            if not _identifier(interface_name, interface=True):
                continue
            metric = _integer(_value(item, "metric"), low=0, high=65535)
            interfaces.append({"name": interface_name,
                               "passive_configured": _first(item, "passive") is not None,
                               "metric": metric})
        areas.append({"id": area_name, "interfaces": interfaces})
    return [{"process_id": None, "process_id_applicability": "not_applicable_junos",
             "areas": areas,
             "reference_bandwidth": _identifier(_value(ospf, "reference-bandwidth")),
             "export_policies": _leaves(ospf, "export"), "import_policies": _leaves(ospf, "import"),
             "source_line": None}]


def _bgp(protos: Any | None, options: Any | None) -> list[dict]:
    bgp = _first(protos, "bgp")
    if bgp is None:
        return []
    global_as = _integer(_value(options, "autonomous-system"), low=1)
    groups = []
    for group_name, group in _named(bgp, "group"):
        local_as = _integer(_value(group, "local-as"), low=1) or global_as
        remote_as = _integer(_value(group, "peer-as"), low=1)
        mode = _value(group, "type")
        families = [tokens[1] for item in _children(group, "family")
                    if (tokens := _parts(item)) and len(tokens) == 2
                    and tokens[1] in {"inet", "inet6", "inet-vpn", "l2vpn", "evpn"}]
        peers = []
        for peer_id, peer in _named(group, "neighbor"):
            if not (_ip_address(peer_id) or _identifier(peer_id, interface=True)):
                continue
            peers.append({"id": peer_id, "remote_as": _integer(_value(peer, "peer-as"), low=1) or remote_as,
                          "local_address": _ip_address(_value(peer, "local-address")) or
                                           _ip_address(_value(group, "local-address")),
                          "authentication_configured": _first(peer, "authentication-key") is not None or
                                                      _first(group, "authentication-key") is not None,
                          "description_configured": _first(peer, "description") is not None,
                          "source_line": None})
        groups.append({"group": group_name, "session_type_configured": mode if mode in
                       ("internal", "external") else None,
                       "local_as": local_as, "remote_as": remote_as,
                       "families": families, "neighbors": peers,
                       "import_policies": _leaves(group, "import"),
                       "export_policies": _leaves(group, "export"),
                       "source_line": None})
    return groups


def _policy_options(section: Any | None) -> tuple[list[dict], list[dict], list[dict]]:
    statements, prefix_lists, communities = [], [], []
    for name, node in _named(section, "prefix-list"):
        prefixes = [_ip_network(_parts(child)[0]) for child in _children(node)
                    if len(_parts(child)) == 1 and not _children(child)]
        prefix_lists.append({"name": name, "prefixes": [p for p in prefixes if p],
                             "dynamic_apply_path_configured": bool(_first(node, "apply-path"))})
    for name, node in _named(section, "community"):
        communities.append({"name": name, "member_count": len(_leaves(node, "members"))})

    def term_parts(node: Any) -> tuple[list[dict], list[dict]]:
        conditions: list[dict] = []
        actions: list[dict] = []
        for branch in _children(node):
            bt = _parts(branch)
            if not bt:
                continue
            children = _children(branch) if len(bt) == 1 else [branch]
            for child in children:
                values = _parts(child) if child is not branch else bt[1:]
                if not values:
                    continue
                if bt[0] == "from":
                    key = values[0]
                    if key in ("protocol", "prefix-list", "community", "rib", "family") and len(values) == 2:
                        if (value := _identifier(values[1])):
                            conditions.append({"kind": key, "values": [value]})
                    elif key == "route-filter" and len(values) >= 3:
                        if (prefix := _ip_network(values[1])) and values[2] in ("exact", "longer", "orlonger"):
                            conditions.append({"kind": "route-filter", "prefix": prefix,
                                               "modifier": values[2]})
                    elif key == "prefix-list-filter" and len(values) == 3:
                        if (name := _identifier(values[1])) and values[2] in ("exact", "longer", "orlonger"):
                            conditions.append({"kind": "prefix-list-filter", "name": name,
                                               "modifier": values[2]})
                elif bt[0] == "then":
                    key = values[0]
                    if key in ("accept", "reject", "next") and len(values) <= 2:
                        actions.append({"kind": key, "next_scope": values[1] if len(values) == 2
                                        and values[1] in ("term", "policy") else None})
                    elif key in ("local-preference", "metric", "tag") and len(values) == 2:
                        if (number := _integer(values[1])) is not None:
                            actions.append({"kind": key, "value": number})
        return conditions, actions

    for name, policy in _named(section, "policy-statement"):
        terms = []
        for order, (term_name, term) in enumerate(_named(policy, "term")):
            conditions, actions = term_parts(term)
            terms.append({"name": term_name, "order": order, "conditions": conditions,
                          "actions": actions})
        if not terms and _children(policy):
            conditions, actions = term_parts(policy)
            if conditions or actions:
                terms.append({"name": None, "order": 0, "conditions": conditions, "actions": actions})
        statements.append({"name": name, "terms": terms})
    return statements, prefix_lists, communities


def _security(section: Any | None) -> tuple[list[dict], list[dict], list[dict]]:
    zones: list[dict] = []
    policies: list[dict] = []
    nat_rules: list[dict] = []
    for name, zone in _named(_first(section, "zones"), "security-zone"):
        ifaces: list[str] = []
        for node in _children(zone, "interfaces"):
            tokens = _parts(node)
            if len(tokens) == 2 and (iface := _identifier(tokens[1], interface=True)):
                ifaces.append(iface)
            else:
                ifaces.extend(_identifier(_parts(child)[0], interface=True)
                              for child in _children(node) if len(_parts(child)) == 1
                              and _identifier(_parts(child)[0], interface=True))
        inbound = _first(zone, "host-inbound-traffic")
        zones.append({"name": name, "interfaces": ifaces,
                      "host_inbound_system_services": _leaves(inbound, "system-services"),
                      "host_inbound_protocols": _leaves(inbound, "protocols")})
    for src_zone, source in _named(_first(section, "policies"), "from-zone"):
        for dst_zone, target in _named(source, "to-zone"):
            for name, policy in _named(target, "policy"):
                matching = _first(policy, "match")
                then = _first(policy, "then")
                action = next((act for act in ("permit", "deny", "reject")
                               if _first(then, act) is not None or _parts(then) == ["then", act]), None)
                policies.append({"name": name, "from_zone": src_zone, "to_zone": dst_zone,
                                 "source_addresses": _leaves(matching, "source-address"),
                                 "destination_addresses": _leaves(matching, "destination-address"),
                                 "applications": _leaves(matching, "application"),
                                 "configured_action": action})
    source_nat = _first(_first(section, "nat"), "source")
    for set_name, rule_set in _named(source_nat, "rule-set"):
        from_zone = _value(_first(rule_set, "from"), "zone")
        to_zone = _value(_first(rule_set, "to"), "zone")
        for rule_name, rule in _named(rule_set, "rule"):
            match = _first(rule, "match")
            then = _first(rule, "then")
            src_nat = _first(then, "source-nat")
            translation = "interface" if (_first(src_nat, "interface") is not None or
                                          _parts(src_nat) == ["source-nat", "interface"]) else None
            nat_rules.append({"kind": "source", "rule_set": set_name, "name": rule_name,
                              "from_zone": _identifier(from_zone), "to_zone": _identifier(to_zone),
                              "source_address": _ip_network(_value(match, "source-address")),
                              "destination_address": _ip_network(_value(match, "destination-address")),
                              "translation": translation})
    return zones, policies, nat_rules


def _firewall(section: Any | None) -> list[dict]:
    filters: list[dict] = []
    for family_name, family in _named(section, "family"):
        if family_name not in ("inet", "inet6"):
            continue
        for name, filter_node in _named(family, "filter"):
            terms = []
            for term_name, term in _named(filter_node, "term"):
                frm = _first(term, "from")
                then = _first(term, "then")
                action = next((act for act in ("accept", "discard", "reject")
                               if _first(then, act) is not None or _parts(then) == ["then", act]), None)
                terms.append({"name": term_name, "protocols": _leaves(frm, "protocol"),
                              "source_addresses": [_ip_network(v) for v in _leaves(frm, "source-address")
                                                   if _ip_network(v)],
                              "destination_addresses": [_ip_network(v) for v in _leaves(frm, "destination-address")
                                                        if _ip_network(v)],
                              "destination_ports": [_integer(v, low=0, high=65535)
                                                    for v in _leaves(frm, "destination-port")
                                                    if _integer(v, low=0, high=65535) is not None],
                              "action": action})
            filters.append({"name": name, "family": family_name, "terms": terms})
    return filters


def safe_junos_parsed_preview(parsed: Any, filename: str) -> dict[str, Any]:
    """Construit l'export JSON uniquement à partir de l'AST tiers, jamais d'IR."""
    roots = {(_parts(node) or [""])[0]: node for node in parsed.config_objs
             if node.parent is node and _parts(node) and (_parts(node)[0] in _SECTIONS)}
    sections: Counter[str] = Counter()
    for node in parsed.config_objs:
        if _children(node) or not _parts(node):
            continue
        root = node
        while root.parent is not root:
            root = root.parent
        label = (_parts(root) or [""])[0]
        if label in _SECTIONS:
            sections[label] += 1

    system = roots.get("system")
    options = roots.get("routing-options")
    protocols = roots.get("protocols")
    interfaces = _interfaces(roots.get("interfaces"))
    instances, instance_routes = _routing_instances(roots.get("routing-instances"), options)
    policies, prefix_lists, communities = _policy_options(roots.get("policy-options"))
    zones, security_policies, nat_rules = _security(roots.get("security"))
    simple_protocols = {}
    for keyword in ("isis", "ldp", "rsvp", "mpls", "evpn", "lldp", "stp"):
        node = _first(protocols, keyword)
        if node is not None:
            simple_protocols[keyword] = {"configured": True,
                                         "interfaces": _leaves(node, "interface", interface=True)}
    names = [item["name"] for item in interfaces]
    present = sorted(({keyword for keyword in _PROTOCOLS if _first(protocols, keyword) is not None}
                      | {keyword for vrf in instances for keyword in vrf["protocols_present"]}))
    return {
        "file": filename, "vendor": "juniper_junos", "parser": parsed.parser_name,
        "syntax": parsed.format, "objects_structured": len(parsed.config_objs),
        "sections_leaf_counts": dict(sorted(sections.items())),
        "hostname": _identifier(_value(system, "host-name")),
        "global_settings": {
            "router_id": _ip_address(_value(options, "router-id")),
            "autonomous_system": _integer(_value(options, "autonomous-system"), low=1),
            "ssh_configured": _first(_first(system, "services"), "ssh") is not None,
        },
        "interfaces": interfaces, "interfaces_identified": names,
        "static_routes": _static_routes(options) + instance_routes,
        "ospf_processes": _ospf(protocols), "bgp_processes": _bgp(protocols, options),
        "routing_instances": instances, "protocols_present": present,
        "additional_protocols": simple_protocols,
        "route_policies": policies, "prefix_lists": prefix_lists, "community_sets": communities,
        "security_zones": zones, "security_policies": security_policies,
        "nat_rules": nat_rules, "access_lists": _firewall(roots.get("firewall")),
        "source_line_notice": "L'AST tiers ne garantit pas les numéros de ligne physiques : source_line=null.",
        "source_only": "Champs sur liste blanche : secrets, descriptions et commandes brutes exclus.",
    }
