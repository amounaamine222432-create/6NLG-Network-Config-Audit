#!/usr/bin/env python3
"""Convertit les extractions du parseur Cisco IOS V6.1 en IR reseau v1.

Sans dependance externe. Aucune configuration n'est appliquee aux routeurs.
Les secrets, hashes et commandes brutes ne sont jamais recopies dans l'IR.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import Any


SCHEMA_VERSION = "1.0.0"
ALLOWED_INPUT_SUFFIXES = {".cfg", ".txt", ".json"}


def _integer(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _ref(obj: dict[str, Any]) -> dict[str, Any]:
    number = obj.get("source_line", obj.get("line"))
    return {"line": number if isinstance(number, int) and number > 0 else None}


def _v4_interface(address: Any, mask: Any) -> tuple[str | None, int | None]:
    try:
        address_object = ipaddress.IPv4Interface(f"{address}/{mask}")
        return str(address_object), address_object.network.prefixlen
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return None, None


def _v4_network(address: Any, mask: Any) -> str | None:
    try:
        return str(ipaddress.IPv4Network(f"{address}/{mask}", strict=False))
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return None


def _acl_address(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    return {key: value[key] for key in ("kind", "address", "wildcard", "name") if key in value}


def _acl_port(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    return {"operator": value.get("operator"), "ports": list(value.get("ports") or [])}


def _vrf_route_targets(items: list[Any]) -> list[dict[str, Any]]:
    result = []
    for value in items:
        parts = str(value).split()
        result.append({"direction": parts[0] if parts else None, "target": parts[1] if len(parts) > 1 else None})
    return result


def _parse_policy_expression(command: str) -> dict[str, Any] | None:
    """Ne normaliser que les expressions de politique reellement comprises."""
    parts = command.split()
    if parts[:4] == ["match", "ip", "address", "prefix-list"] and len(parts) >= 5:
        return {"operation": "match_prefix_list", "references": parts[4:]}
    if parts[:3] == ["match", "ip", "address"] and len(parts) >= 4:
        return {"operation": "match_acl", "references": parts[3:]}
    if parts[:2] == ["match", "community"] and len(parts) >= 3:
        return {"operation": "match_community_list", "references": parts[2:]}
    if parts[:2] == ["set", "local-preference"] and len(parts) == 3:
        number = _integer(parts[2])
        if number is not None:
            return {"operation": "set_local_preference", "value": number}
    if parts[:2] == ["set", "metric"] and len(parts) == 3:
        value = _integer(parts[2])
        if value is not None:
            return {"operation": "set_metric", "value": value}
    if parts[:2] == ["set", "community"] and len(parts) >= 3:
        additive = parts[-1] == "additive"
        communities = parts[2:-1] if additive else parts[2:]
        if communities:
            return {"operation": "set_bgp_communities", "communities": communities,
                    "additive": additive}
    if parts[:3] == ["set", "as-path", "prepend"] and len(parts) >= 4:
        values = [_integer(part) for part in parts[3:]]
        if all(value is not None for value in values):
            return {"operation": "prepend_as_path", "autonomous_systems": values}
    return None


def normalize_cisco_ios(
    parsed: dict[str, Any], *, source_file: str | None = None,
    sha256: str | None = None,
) -> dict[str, Any]:
    """IR structurée d'un Cisco IOS deja parse ; sans effet de bord.

    Tout champ non modele est signale dans diagnostics, ou reste disponible
    dans le JSON brut du parser V6 (non incorpore pour eviter les secrets).
    """
    if parsed.get("vendor") != "cisco_ios":
        raise ValueError("Une extraction provenant du parseur Cisco IOS est requise")
    if parsed.get("source_cli_family") in {"ios_xr", "ios_xr_candidate"}:
        raise ValueError("Syntaxe IOS XR detectee ou suspectee : normalisation IOS refusee, parser XR dedie requis")

    g = parsed.get("global_settings") or {}
    opaque_sections: list[dict[str, Any]] = []
    notes: list[str] = []

    platform_directives = []
    platform_unmodeled = 0
    platform_unverified = 0
    platform_scope_limited = 0
    for entry in parsed.get("platform_commands", []):
        modeled = entry.get("structured")
        if not isinstance(modeled, dict):
            platform_unmodeled += 1
            continue
        if modeled.get("documentation_status") == "syntax_only":
            platform_unverified += 1
        elif modeled.get("documentation_status") == "vendor_documented_platform_specific":
            platform_scope_limited += 1
        platform_directives.append({
            "feature": modeled.get("feature"),
            "configured_value": modeled.get("configured_value"),
            "value_unit": modeled.get("unit"),
            "documentation_status": modeled.get("documentation_status"),
            "documented_meaning": modeled.get("documented_meaning"),
            "documentation_scope": modeled.get("documentation_scope"),
            "documentation_reference": modeled.get("documentation_reference"),
            "operational_state": None,
            "source": _ref(entry),
        })
    if platform_unverified:
        notes.append("Certaines directives de plateforme sont reconnues sans sémantique documentée.")
    if platform_scope_limited:
        notes.append("La sémantique MMI est documentée pour Cisco SOHO 76/77 ; sa transposition à IOS 15.x et au matériel cible reste à confirmer.")
    if platform_unmodeled:
        notes.append("Certaines variantes de directives de plateforme demandent une prise en charge supplémentaire.")
    if parsed.get("formatting_recoveries"):
        notes.append("Des commandes de sous-section sans indentation ont été récupérées explicitement ; vérifier le format source.")

    def opaque(scope: str, commands: Any, line: int | None = None) -> None:
        size = len(commands) if isinstance(commands, list) else 0
        if size:
            opaque_sections.append({"section": scope, "count": size, "source": {"line": line}})

    device = {
        "hostname": parsed.get("hostname"),
        "platform": {"vendor": "cisco", "family": "ios", "version": g.get("ios_version")},
        "platform_directives": platform_directives,
    }

    vrfs = [{
        "name": v.get("name"), "route_distinguisher": v.get("rd"),
        "description": v.get("description"),
        "address_families": list(v.get("address_families") or []),
        "route_targets": _vrf_route_targets(v.get("route_targets") or []),
        "source": _ref(v),
    } for v in parsed.get("vrfs", [])]

    interfaces = []
    for iface in parsed.get("interfaces", []):
        addr = []
        for address in iface.get("ipv4_addresses", []):
            cidr, prefix = _v4_interface(address.get("address"), address.get("mask"))
            if cidr is None:
                notes.append("Adresse ou masque IPv4 non normalisable : verifier la source de l'interface.")
            addr.append({
                "address": address.get("address"), "prefix_length": prefix,
                "cidr": cidr, "secondary": "secondary" in (address.get("options") or []),
            })
        admin_command = iface.get("administrative_command")
        admin_enabled = (True if admin_command == "no shutdown" else
                         False if admin_command == "shutdown" else None)
        interface_hsrp = [{
            "group_id": _integer(h.get("group_id")), "virtual_ipv4": h.get("virtual_ip"),
            "priority": _integer(h.get("priority")), "preempt": bool(h.get("preempt")),
            "authentication_configured": bool(h.get("authentication_configured")),
            "tracking_rule_count": len(h.get("track_commands") or []),
        } for h in iface.get("hsrp_groups", [])]
        switchport = iface.get("switchport") or {}
        dot1q = iface.get("dot1q") or {}
        interfaces.append({
            "name": iface.get("name"), "description": iface.get("description"),
            "admin_enabled": admin_enabled, "operational_state": None,
            "link": {"speed": iface.get("speed"), "duplex": iface.get("duplex"),
                     "media_type": iface.get("media_type"),
                     "mtu": _integer(iface.get("mtu")),
                     "auto_negotiation": iface.get("negotiation") == "auto" if iface.get("negotiation") else None,
                     "cdp_enabled": iface.get("cdp_enabled")},
            "ipv4_addresses": addr, "ipv4_dhcp": bool(iface.get("ipv4_dhcp")),
            "ipv4_explicitly_absent": bool(iface.get("no_ip_address")),
            "vrf": iface.get("vrf_forwarding"), "nat_role": iface.get("nat_role"),
            "proxy_arp_enabled": iface.get("proxy_arp_enabled"),
            "acl_bindings": [{"name": b.get("name"), "direction": b.get("direction")}
                             for b in iface.get("acl_bindings") or []],
            "ospf_network_type": iface.get("ospf_network_type"),
            "ospf_authentication_mode": iface.get("ospf_authentication_mode"),
            "ospf_md5_key_ids": [str(k["key_id"]) for k in iface.get("ospf_md5_keys", [])],
            "eigrp_authentication": dict(iface.get("eigrp_authentication") or {}),
            "dhcp_relay_targets": list(iface.get("ip_helper_addresses") or []),
            "vlan_tagging": ({"vlan_id": _integer(dot1q.get("vlan_id")),
                             "native": bool(dot1q.get("native"))} if dot1q else None),
            "switchport": {
                "mode": switchport.get("mode"), "access_vlan": _integer(switchport.get("access_vlan")),
                "native_vlan": _integer(switchport.get("native_vlan")),
                "trunk_encapsulation": switchport.get("trunk_encapsulation"),
                "allowed_vlan_expressions": list(switchport.get("allowed_vlan_commands") or []),
            },
            "hsrp_groups": interface_hsrp,
            "source": _ref(iface),
        })
        opaque(f"interface:{iface.get('name')}", iface.get("other_commands"), _ref(iface)["line"])
        for h in iface.get("hsrp_groups", []):
            opaque(f"hsrp:{iface.get('name')}", h.get("other_commands"), _ref(iface)["line"])

    ospf = []
    for process in parsed.get("ospf_processes", []):
        redistributed = []
        unmodeled_redistribution = 0
        for command in process.get("redistribution_commands") or []:
            if command.split() == ["redistribute", "connected", "subnets"]:
                redistributed.append({"source_protocol": "connected", "include_subnets": True})
            else:
                unmodeled_redistribution += 1
        ospf.append({
            "process_id": str(process.get("process_id")), "router_id": process.get("router_id"),
            "network_selectors": [{"address": x.get("network"),
                                   "wildcard": x.get("wildcard_mask"), "area": str(x.get("area"))}
                                  for x in process.get("networks", [])],
            "passive_interfaces": list(process.get("passive_interfaces") or []),
            "area_authentication": list(process.get("area_authentication") or []),
            "non_passive_interfaces": list(process.get("non_passive_interfaces") or []),
            "redistribution_present": bool(process.get("redistribution_commands")),
            "redistribution_statement_count": len(process.get("redistribution_commands") or []),
            "redistribution_rules": redistributed,
            "unmodeled_redistribution_count": unmodeled_redistribution,
            "default_information_originate": process.get("default_information_originate"),
            "default_information_options": list(process.get("default_information_options") or []),
            "source": _ref(process),
        })
        opaque("ospf", process.get("other_commands"), _ref(process)["line"])
        if unmodeled_redistribution:
            opaque("ospf-redistribution", [None] * unmodeled_redistribution, _ref(process)["line"])
            notes.append("Les conditions detaillees de redistribution OSPF ne sont pas encore normalisees.")

    eigrp = [{
        "identifier": p.get("identifier"),
        "address_families": list(p.get("address_families") or []),
        "networks": list(p.get("networks") or []),
        "passive_interfaces": list(p.get("passive_interfaces") or []),
        "af_interfaces": dict(p.get("af_interfaces") or {}),
        "auto_summary_enabled": p.get("auto_summary_enabled"),
        "unmodeled_command_count": p.get("other_count") or 0,
        "source": _ref(p),
    } for p in parsed.get("eigrp_processes", [])]
    key_chains = [{
        "name": k.get("name"), "key_count": len(k.get("key_ids") or []),
        "key_string_count": len(set(k.get("key_string_key_ids") or [])),
        "source": _ref(k),
    } for k in parsed.get("key_chains", [])]

    bgp = []
    for process in parsed.get("bgp_processes", []):
        peers = []
        peer_groups = {n.get("id"): n for n in process.get("neighbors", []) if n.get("is_peer_group")}
        for neighbor in process.get("neighbors", []):
            effective_as = neighbor.get("effective_remote_as") or neighbor.get("remote_as")
            policies = [{
                "policy_name": p.get("name"), "direction": p.get("direction"),
                "address_family": p.get("address_family"), "source": _ref(p),
            } for p in neighbor.get("route_maps", [])]
            group_config = peer_groups.get(neighbor.get("peer_group")) or {}
            # Ne conserver que la présence d'un mot de passe BGP, jamais sa valeur.
            password_local = bool(neighbor.get("password_configured"))
            password_group = bool(group_config.get("password_configured"))
            inherited_policies = [{
                "policy_name": p.get("name"), "direction": p.get("direction"),
                "address_family": p.get("address_family"),
                "inherited_from": neighbor.get("peer_group"), "source": _ref(p),
            } for p in group_config.get("route_maps", [])]
            # Pour le MVP, maintenir les references locales ET heritees sans
            # deduire les eventuelles regles de precedence propres a IOS.
            peers.append({
                "id": neighbor.get("id"), "kind": "peer_group" if neighbor.get("is_peer_group") else "peer",
                "peer_group": neighbor.get("peer_group"),
                "remote_as": _integer(effective_as),
                "remote_as_unparsed": (str(effective_as) if effective_as is not None and _integer(effective_as) is None else None),
                "remote_as_inherited_from": neighbor.get("remote_as_inherited_from"),
                "session_type_configured": neighbor.get("session_type_configured"),
                "update_source": neighbor.get("update_source"),
                "description_configured": bool(neighbor.get("description_configured")),
                "password_configured": password_local or password_group,
                "password_inherited_from": (neighbor.get("peer_group")
                                            if password_group and not password_local else None),
                "password_in_af_unverified": bool(neighbor.get("password_in_af_unverified")),
                "description_source": ({"line": neighbor["description_source_line"]}
                                       if neighbor.get("description_source_line") else None),
                "activated_families": list(neighbor.get("activated_families") or []),
                "policies": policies, "inherited_policy_references": inherited_policies,
                "send_community_by_family": dict(neighbor.get("send_community_by_family") or {}),
                "advertise_additional_paths": list(neighbor.get("advertise_additional_paths") or []),
                "route_reflector_client_families": list(neighbor.get("route_reflector_client_families") or []),
                "source": _ref(neighbor),
            })
            # Ne jamais copier global_commands (peuvent inclure "neighbor ... password").
            excluded_global = []
            for command in neighbor.get("global_commands", []):
                parts = str(command).split()
                if (not parts or parts[0] not in
                        {"peer-group", "remote-as", "update-source", "send-community"}
                        and parts != ["route-reflector-client"]
                        and parts != ["advertise", "additional-paths", "all"]
                        and not (parts[0] == "description" and len(parts) >= 2
                                 and neighbor.get("description_configured"))
                        and not (len(parts) == 3 and parts[0] == "route-map"
                                 and parts[2] in {"in", "out"}
                                 and any(policy.get("name") == parts[1]
                                         and policy.get("direction") == parts[2]
                                         and policy.get("address_family") is None
                                         for policy in neighbor.get("route_maps", [])))):
                    excluded_global.append(None)
            opaque("bgp-neighbor", excluded_global, _ref(neighbor)["line"])
            excluded_af = []
            for commands in (neighbor.get("address_family_commands") or {}).values():
                for command in commands:
                    parts = str(command).split()
                    if (parts != ["activate"] and parts != ["peer-group"]
                            and parts != ["route-reflector-client"]
                            and parts != ["advertise", "additional-paths", "all"]
                            and (not parts or parts[0] not in {"route-map", "send-community"})):
                        excluded_af.append(None)
            opaque("bgp-neighbor-af", excluded_af, _ref(neighbor)["line"])
        networks = []
        for network in process.get("network_statements", []):
            mask = network.get("mask")
            prefix = _v4_network(network.get("prefix"), mask) if mask else None
            if mask is None:
                notes.append("Annonce BGP sans masque explicite : prefixe non deduit arbitrairement.")
            networks.append({"prefix": prefix, "address": network.get("prefix"),
                             "mask": mask, "address_family": network.get("address_family"),
                             "source": _ref(network)})
        bgp.append({
            "local_as": _integer(process.get("local_as")),
            "router_id": process.get("router_id"), "neighbors": peers,
            "log_neighbor_changes": process.get("log_neighbor_changes"),
            "network_statements": networks,
            "address_families": [f.get("name") for f in process.get("address_families", [])],
            "address_family_features": [{
                "name": f.get("name"),
                "dampening_configured": f.get("dampening_configured"),
                "additional_paths": list(f.get("additional_paths_commands") or []),
                "maximum_paths_eibgp": _integer(f.get("maximum_paths_eibgp")),
                "aggregates": [{
                    "prefix": _v4_network(a.get("address"), a.get("mask")),
                    "summary_only": bool(a.get("summary_only")), "source": _ref(a),
                } for a in f.get("aggregate_addresses") or []],
            } for f in process.get("address_families", [])],
            "source": _ref(process),
        })
        opaque("bgp", process.get("other_commands"), _ref(process)["line"])
        for family in process.get("address_families", []):
            opaque("bgp-address-family", family.get("other_commands"), _ref(family)["line"])

    routes = []
    for route in parsed.get("static_routes", []):
        prefix = _v4_network(route.get("destination"), route.get("mask"))
        if prefix is None:
            notes.append("Route IPv4 statique avec masque non normalisable.")
        routes.append({
            "prefix": prefix, "destination": route.get("destination"),
            "mask": route.get("mask"), "vrf": route.get("vrf"),
            "next_hop": route.get("next_hop"),
            "outgoing_interface": route.get("outgoing_interface"),
            "administrative_distance": _integer(route.get("administrative_distance_configured")),
            "unmodeled_option_count": max(0, len(route.get("options") or []) -
                                          (1 if route.get("administrative_distance_configured") is not None else 0)),
            "source": _ref(route),
        })

    acl = []
    for a in parsed.get("access_lists", []):
        entries = []
        for entry in a.get("entries", []):
            entries.append({
                "sequence": _integer(entry.get("sequence")), "action": entry.get("action"),
                "protocol": entry.get("protocol"),
                "source_match": _acl_address(entry.get("source")),
                "destination_match": _acl_address(entry.get("destination")),
                "source_port": _acl_port(entry.get("source_port")),
                "destination_port": _acl_port(entry.get("destination_port")),
                "logging_mode": entry.get("logging_mode"),
                "unmodeled_token_count": len(entry.get("remaining_tokens") or []),
                "source": _ref(entry),
            })
        acl.append({"name": a.get("name"), "type": a.get("acl_type"), "entries": entries})
        opaque("acl", a.get("other_commands"))

    prefixes = [{
        "name": p.get("name"), "entries": [{
            "sequence": _integer(e.get("sequence")), "action": e.get("action"),
            "prefix": e.get("prefix"), "min_length": _integer(e.get("ge")),
            "max_length": _integer(e.get("le")), "source": _ref(e),
        } for e in p.get("entries", [])],
    } for p in parsed.get("prefix_lists", [])]

    route_maps = []
    for rm in parsed.get("route_maps", []):
        entries = []
        for e in rm.get("entries", []):
            understood = []
            unmodeled = 0
            for cmd in (e.get("match_commands") or []) + (e.get("set_commands") or []):
                operation = _parse_policy_expression(cmd)
                if operation is None:
                    unmodeled += 1
                else:
                    understood.append(operation)
            entries.append({
                "sequence": _integer(e.get("sequence")), "action": e.get("action"),
                "operations": understood,
                "unmodeled_statement_count": unmodeled + len(e.get("other_commands") or []),
                "source": _ref(e),
            })
            if unmodeled:
                opaque(f"route-map:{rm.get('name')}", [None] * unmodeled, _ref(e)["line"])
            opaque(f"route-map:{rm.get('name')}", e.get("other_commands"), _ref(e)["line"])
        route_maps.append({"name": rm.get("name"), "entries": entries})

    communities = []
    for c in parsed.get("community_lists", []):
        entries = []
        unmodeled = 0
        for e in c.get("entries") or []:
            definition = str(e.get("definition") or "").split()
            if len(definition) >= 2 and definition[0] in {"permit", "deny"}:
                entries.append({"action": definition[0], "communities": definition[1:],
                                "source": _ref(e)})
            else:
                unmodeled += 1
        communities.append({"name": c.get("name"), "kind": c.get("community_type"),
                            "entry_count": len(c.get("entries") or []),
                            "entries": entries, "unmodeled_entry_count": unmodeled})
        if unmodeled:
            opaque("community-list", [None] * unmodeled)
            notes.append("Certaines expressions community-list demandent une interprétation supplémentaire.")

    nat = []
    for n in parsed.get("nat_rules", []):
        nat.append({
            "kind": n.get("kind"), "source_acl": n.get("acl"),
            "pool": n.get("pool"), "interface": n.get("interface"),
            "overload": bool(n.get("overload")), "protocol": n.get("protocol"),
            "inside_local": n.get("inside_local"), "inside_global": n.get("inside_global"),
            "inside_port": _integer(n.get("inside_port")),
            "outside_port": _integer(n.get("outside_port")), "source": _ref(n),
        })
    nat_pools = [{
        "name": p.get("name"), "start_address": p.get("start_address"),
        "end_address": p.get("end_address"),
        "source": _ref(p),
    } for p in parsed.get("nat_pools", [])]

    dhcp_pools = [{
        "name": p.get("name"),
        "subnet": (_v4_network((p.get("network") or {}).get("address"),
                               (p.get("network") or {}).get("mask_or_prefix"))
                   if p.get("network") else None),
        "gateways": list(p.get("default_routers") or []),
        "dns_servers": list(p.get("dns_servers") or []),
        "domain_name": p.get("domain_name"),
        "lease": ({"infinite": bool(p["lease"].get("infinite")),
                   "duration_seconds": p["lease"].get("duration_seconds"),
                   "source": _ref(p["lease"])}
                  if isinstance(p.get("lease"), dict) else None),
    } for p in parsed.get("dhcp_pools", [])]

    snmp = parsed.get("snmp") or {}
    syslog = parsed.get("syslog") or {}
    ntp = parsed.get("ntp") or {}
    def normalize_ntp_targets(targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized = []
        for server in targets:
            normalized.append({
                "target": server.get("target"), "vrf": server.get("vrf"),
                "source_interface": server.get("source_interface"),
                "version": _integer(server.get("version")),
                "prefer": bool(server.get("prefer")),
                "authentication_key_referenced": server.get("key_id") is not None,
                "authentication_key_id": str(server.get("key_id")) if server.get("key_id") is not None else None,
                "unmodeled_token_count": server.get("unmodeled_token_count") or 0,
                "source": _ref(server),
            })
            if server.get("unmodeled_token_count"):
                opaque("ntp-peer-options", [None] * server["unmodeled_token_count"], _ref(server)["line"])
        return normalized

    management_lines = [{
        "line_id": line.get("identifier"),
        "transport_input": list(line.get("transport_input") or []),
        "login_method": line.get("login_method"),
        "access_classes": [{"acl": item.get("acl"), "direction": item.get("direction"),
                            "vrf_also": bool(item.get("vrf_also"))}
                           for item in line.get("access_classes", [])],
        "exec_timeout": list(line.get("exec_timeout") or []),
        "privilege_level": _integer(line.get("privilege_level")),
        "stopbits": _integer(line.get("stopbits")),
        "line_password_configured": bool(line.get("password_configured")),
        "source": _ref(line),
    } for line in parsed.get("lines", [])]

    ssh_version = None
    for command in g.get("ssh_commands") or []:
        parts = str(command).split()
        if len(parts) == 4 and parts[:3] == ["ip", "ssh", "version"] and parts[3] in {"1", "2"}:
            ssh_version = int(parts[3])

    # Compter aussi les blocs opaques hors interfaces/routeurs.
    for section, items in (("snmp", snmp.get("other_commands")),
                           ("syslog", syslog.get("other_commands")),
                           ("nat", parsed.get("nat_other_commands")),
                           ("dhcp", parsed.get("dhcp_other_commands"))):
        opaque(section, items)
    for p in parsed.get("dhcp_pools", []):
        opaque("dhcp_pool", p.get("other_commands"))
    for line in parsed.get("lines", []):
        opaque("line", line.get("other_commands"), _ref(line)["line"])
    for v in parsed.get("vrfs", []):
        opaque("vrf", v.get("other_commands"), _ref(v)["line"])
    for v in parsed.get("vlans", []):
        opaque("vlan", v.get("other_commands"))

    result = {
        "schema_version": SCHEMA_VERSION,
        "source": {"vendor": "cisco_ios", "parser_schema_version": parsed.get("parser_schema_version"),
                   "file": source_file or parsed.get("source_file"), "sha256": sha256},
        "device": device,
        "vrfs": vrfs,
        "interfaces": interfaces,
        "routing": {"static_routes": routes, "ospf": ospf, "eigrp": eigrp,
                    "key_chains": key_chains, "bgp": bgp},
        "policies": {"acls": acl, "prefix_lists": prefixes, "route_maps": route_maps,
                     "community_lists": communities},
        "services": {
            "nat": {"rules": nat, "pools": nat_pools,
                    "translation_timers": dict(parsed.get("nat_translation_settings") or {})},
            "dhcp": {"pools": dhcp_pools, "excluded_ranges": [
                list(e.get("addresses") or []) for e in parsed.get("dhcp_excluded_addresses", [])]},
            "vlans": [{"id": _integer(v.get("name")), "name": v.get("configured_name")}
                      for v in parsed.get("vlans", [])],
            "snmp": {"communities": [{"access": str(c.get("access") or "unknown").lower(),
                                        "secret_redacted": True, "source": _ref(c)}
                                       for c in snmp.get("communities", [])],
                     "targets": [{"address": h.get("host"), "version": h.get("version"),
                                  "source": _ref(h)} for h in snmp.get("hosts", [])],
                     "location_configured": snmp.get("location_configured"),
                     "contact_configured": snmp.get("contact_configured"),
                     "groups": [{"version": group.get("version"),
                                 "security_level": group.get("security_level"),
                                 "read_configured": bool(group.get("read_configured")),
                                 "write_configured": bool(group.get("write_configured")),
                                 "notify_configured": bool(group.get("notify_configured")),
                                 "access_restricted": bool(group.get("access_restricted")),
                                 "source": _ref(group)}
                                for group in snmp.get("groups", [])],
                     "users": [{"version": user.get("version"),
                                "remote": bool(user.get("remote")),
                                "authentication_configured": bool(user.get("authentication_configured")),
                                "authentication_algorithm": user.get("authentication_algorithm"),
                                "privacy_configured": bool(user.get("privacy_configured")),
                                "privacy_algorithm": user.get("privacy_algorithm"),
                                "access_restricted": bool(user.get("access_restricted")),
                                "secrets_redacted": True,
                                "source": _ref(user)}
                               for user in snmp.get("users", [])],
                     "trap_rules": [{"family": (t.get("family") if t.get("family") in {
                                         "all", "snmp", "bgp", "ospf", "syslog", "config", "hsrp",
                                         "envmon", "entity", "link", "tty", "eigrp", "cpu", "memory"
                                     } else "other"),
                                     "option_count": int(t.get("option_count") or 0),
                                     "source": _ref(t)}
                                    for t in snmp.get("trap_rules", [])],
                     "traps_explicitly_disabled": snmp.get("traps_enabled") is False},
            "syslog": {"targets": [{"address": h.get("host"), "source": _ref(h)}
                                   for h in syslog.get("hosts", [])],
                       "source_interface": syslog.get("source_interface"),
                       "severity": syslog.get("trap_level"),
                       "buffered": ({"enabled": syslog["buffered"].get("enabled"),
                                     "size_bytes": syslog["buffered"].get("size_bytes"),
                                     "severity": syslog["buffered"].get("severity"),
                                     "discriminator_configured": bool(syslog["buffered"].get("discriminator_configured")),
                                     "source": _ref(syslog["buffered"])}
                                    if isinstance(syslog.get("buffered"), dict) else None)},
            "ntp": {
                "servers": normalize_ntp_targets(ntp.get("servers") or []),
                "peers": normalize_ntp_targets(ntp.get("peers") or []),
                "source_interface": ntp.get("source_interface"),
                "authentication_enabled": ntp.get("authentication_enabled"),
                "authentication_key_count": len(ntp.get("authentication_keys") or []),
                "trusted_key_count": len(ntp.get("trusted_key_ids") or []),
                "defined_key_ids": sorted({str(k.get("key_id")) for k in ntp.get("authentication_keys") or []
                                           if isinstance(k, dict) and k.get("key_id") is not None}),
                "trusted_key_ids": sorted({str(k) for k in ntp.get("trusted_key_ids") or []}),
                "master_configured": ntp.get("master_configured"),
                "master_stratum": ntp.get("master_stratum"),
                "access_groups": [{"mode": entry.get("mode"), "acl": entry.get("acl")}
                                  for entry in ntp.get("access_groups") or []],
            },
            "ip_stack": {
                "icmp_unreachable_rate_limit": g.get("icmp_unreachable_rate_limit"),
                "tcp_synwait_seconds": g.get("tcp_synwait_seconds"),
                "source_route_enabled": g.get("ip_source_route_enabled"),
            },
            "clock": {
                "timezone": (
                    {"name": g["clock_timezone"].get("name"),
                     "hours_offset": g["clock_timezone"].get("hours_offset"),
                     "minutes_offset": g["clock_timezone"].get("minutes_offset"),
                     "source": _ref(g["clock_timezone"])}
                    if isinstance(g.get("clock_timezone"), dict) else None
                ),
                # Operational time synchronization requires live evidence.
                "synchronized": None,
            },
        },
        "management": {
            "http_enabled": g.get("http_server_enabled"),
            "https_enabled": g.get("https_server_enabled"),
            "ssh_version": ssh_version,
            "terminal_lines": management_lines,
            "local_accounts": [{"name": u.get("name"), "privilege": _integer(u.get("privilege")),
                                "credential_configured": bool(u.get("credential_configured")),
                                "credential_type": u.get("credential_kind"), "source": _ref(u)}
                               for u in parsed.get("local_users", [])],
            "banners": [{"kind": b.get("kind"), "source": _ref(b)}
                        for b in parsed.get("banners", [])],
            "enable_secret_configured": g.get("enable_secret_configured"),
            "enable_password_configured": g.get("enable_password_configured"),
            "aaa_new_model_enabled": g.get("aaa_new_model_enabled"),
            "aaa_authentication_login": [{"name": m.get("name"), "methods": list(m.get("methods") or []),
                                          "source": _ref(m)}
                                         for m in g.get("aaa_authentication_login") or []],
            "aaa_authentication_enable": [{"name": m.get("name"), "methods": list(m.get("methods") or []),
                                           "source": _ref(m)}
                                          for m in g.get("aaa_authentication_enable") or []],
            "aaa_login_privilege_mode": g.get("aaa_login_privilege_mode"),
            "rsa_key_generation_requests": [
                {"modulus": key.get("modulus"), "source": _ref(key)}
                for key in g.get("rsa_key_generation_requests") or []
            ],
        },
        "diagnostics": {
            "unparsed_global_count": len(parsed.get("unparsed_lines", [])),
            "unparsed_global_lines": [u.get("line") for u in parsed.get("unparsed_lines", [])],
            "platform_opaque_count": platform_unmodeled,
            "platform_directive_count": len(parsed.get("platform_commands", [])),
            "platform_modeled_count": len(platform_directives),
            "platform_semantics_unverified_count": platform_unverified,
            "platform_scope_limited_count": platform_scope_limited,
            "formatting_recovery_count": len(parsed.get("formatting_recoveries") or []),
            "opaque_sections": opaque_sections,
            "source_only_counts": {
                "cli_wrappers": len(parsed.get("wrapper_commands", [])),
                "timestamps_directives": len(g.get("service_timestamps") or []),
                "other_global_service_directives": len(g.get("service_commands") or []),
                "other_system_stanzas": len(parsed.get("system_stanzas", [])),
                "configuration_metadata": len(parsed.get("configuration_metadata", [])),
                "bgp_community_new_format_configured": g.get("bgp_community_new_format"),
            },
            "notes": sorted(set(notes)),
            "status": "partial" if parsed.get("unparsed_lines") or
                      platform_unmodeled or platform_unverified or platform_scope_limited or
                      opaque_sections or notes else "modeled_subset",
        },
    }
    validate_ir(result)
    return result


def validate_ir(ir: dict[str, Any]) -> None:
    """Controle structurel leger sans jsonschema ; le schema formel est dans schemas/."""
    keys = {"schema_version", "source", "device", "vrfs", "interfaces", "routing",
            "policies", "services", "management", "diagnostics"}
    if set(ir) != keys:
        raise ValueError(f"Champs IR racine manquants/inattendus : {keys ^ set(ir)}")
    if ir["schema_version"] != SCHEMA_VERSION:
        raise ValueError("Version du schema IR inattendue")
    for name in ("source", "device", "routing", "policies", "services", "management", "diagnostics"):
        if not isinstance(ir[name], dict):
            raise ValueError(f"{name} doit etre un objet JSON")
    for name in ("interfaces", "vrfs"):
        if not isinstance(ir[name], list):
            raise ValueError(f"{name} doit etre un tableau JSON")
    if not isinstance(ir["device"].get("hostname"), (str, type(None))):
        raise ValueError("device.hostname doit etre une chaine ou null")
    for iface in ir["interfaces"]:
        if iface.get("admin_enabled") not in (True, False, None):
            raise ValueError("interface.admin_enabled doit etre true, false ou null")
        for addr in iface.get("ipv4_addresses", []):
            if addr["cidr"] is not None:
                ipaddress.IPv4Interface(addr["cidr"])


def _parse_source(path: Path) -> dict[str, Any]:
    if path.suffix.lower() == ".json":
        parsed = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(parsed, dict):
            raise ValueError(f"Extraction JSON incorrecte : {path}")
        return parsed
    try:
        from cisco_parser import parse_cisco_ios
    except ModuleNotFoundError:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "parsers"))
        from cisco_parser import parse_cisco_ios
    return parse_cisco_ios(path.read_text(encoding="utf-8-sig"))


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(description="Normalisation Cisco IOS V6 vers IR reseau v1 (JSON)")
    cli.add_argument("source", type=Path, help="Configuration .cfg/.txt, JSON parse V6 ou repertoire")
    cli.add_argument("--output-dir", type=Path, default=Path("data/ir"), help="Repertoire de sortie")
    args = cli.parse_args(argv)
    if not args.source.exists():
        cli.error(f"Source introuvable : {args.source}")
    src_dir = args.source if args.source.is_dir() else args.source.parent
    files = (sorted(f for f in src_dir.rglob("*") if f.is_file() and f.suffix.lower() in ALLOWED_INPUT_SUFFIXES)
             if args.source.is_dir() else [args.source])
    if not files:
        cli.error("Aucun fichier .cfg/.txt/.json trouve")
    failures = 0
    for path in files:
        try:
            raw = path.read_bytes()
            parsed = _parse_source(path)
            relative = path.relative_to(src_dir)
            ir = normalize_cisco_ios(parsed, source_file=str(relative),
                                     sha256=hashlib.sha256(raw).hexdigest())
            target = args.output_dir / relative.parent / f"{path.stem}.ir.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(ir, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            print(f"[OK] {relative} -> {target} | interfaces={len(ir['interfaces'])}, "
                  f"OSPF={len(ir['routing']['ospf'])}, BGP={len(ir['routing']['bgp'])}, "
                  f"globales non parsees={ir['diagnostics']['unparsed_global_count']}")
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            failures += 1
            print(f"[ECHEC] {path} : {exc}", file=sys.stderr)
    print(f"RESULTAT : {len(files) - failures}/{len(files)} configurations normalisees")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
