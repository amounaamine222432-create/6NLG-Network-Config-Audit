"""Conservative, read-only IOS coherence diagnostics on the normalized IR.

These findings are NOT CIS verdicts. Uncertain cases remain UNKNOWN so that
incomplete topology, VRF and advanced ACL syntax do not become false alarms.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict


def _finding(code, status, severity, description, evidence, recommendation):
    source_lines = set()
    def collect(value):
        if isinstance(value, dict):
            line = value.get("source_line")
            if type(line) is int and line > 0:
                source_lines.add(line)
            for candidate in value.get("source_lines") or []:
                if type(candidate) is int and candidate > 0:
                    source_lines.add(candidate)
            for field, nested in value.items():
                if field not in {"source_line", "source_lines"}:
                    collect(nested)
        elif isinstance(value, list):
            for nested in value:
                collect(nested)
    collect(evidence)
    return {"rule_id": code, "status": status, "severity": severity,
            "description": description, "evidence": evidence,
            "recommendation": recommendation,
            "source_lines": sorted(source_lines)[:24]}


def _ipnet(value):
    try:
        return ipaddress.ip_network(str(value), strict=False)
    except (ValueError, TypeError):
        return None


def _ipaddr(value):
    try:
        return ipaddress.ip_address(str(value))
    except (ValueError, TypeError):
        return None


def _source(item):
    return (item.get("source") or {}).get("line")


def _acl_address(match):
    if not isinstance(match, dict):
        return None
    kind = match.get("kind")
    if kind == "any":
        return _ipnet("0.0.0.0/0")
    if kind == "host":
        return _ipnet(f"{match.get('address')}/32")
    if kind == "network_wildcard":
        try:
            wild = int(ipaddress.IPv4Address(match.get("wildcard")))
            mask = ipaddress.IPv4Address(0xffffffff ^ wild)
            return _ipnet(f"{match.get('address')}/{mask}")
        except (ValueError, TypeError):
            return None
    return None


def _shadowable(acl_type, entry):
    """Only model exact, port-free IPv4 any/host/network ACL entries."""
    if entry.get("action") not in {"permit", "deny"}:
        return None
    if entry.get("unmodeled_token_count"):
        return None
    if entry.get("source_port") or entry.get("destination_port"):
        return None
    src = _acl_address(entry.get("source_match"))
    if src is None:
        return None
    if acl_type == "standard":
        return ("ip", src, _ipnet("0.0.0.0/0"))
    proto = entry.get("protocol")
    dst = _acl_address(entry.get("destination_match"))
    if not dst or proto not in {"ip", "tcp", "udp", "icmp"}:
        return None
    return (proto, src, dst)


def audit_network_coherence(ir: dict, *, complete_config: bool = False) -> dict:
    """Return independent supplemental findings, never modifying the CIS score."""
    routes = (ir.get("routing") or {}).get("static_routes") or []
    interfaces = ir.get("interfaces") or []
    acls = (ir.get("policies") or {}).get("acls") or []
    findings = []

    # Distinct next-hops for the same destination are ambiguous: ECMP or
    # floating static routes may be intentional. Report REVIEW, not FAIL.
    groups = defaultdict(list)
    for route in routes:
        if not isinstance(route, dict):
            continue
        net = _ipnet(route.get("prefix"))
        if net:
            groups[(str(route.get("vrf") or "global"), str(net))].append(route)
    conflicts = []
    for (vrf, prefix), entries in groups.items():
        hops = {(r.get("next_hop"), r.get("outgoing_interface"),
                 r.get("administrative_distance")) for r in entries}
        if len(hops) > 1:
            conflicts.append({"vrf": vrf, "prefix": prefix,
                              "source_lines": [_source(r) for r in entries],
                              "variants": len(hops)})
    findings.append(_finding("ROUTE_CONFLICT", "REVIEW" if conflicts else "PASS",
        "MEDIUM", "Routes statiques multiples vers un même préfixe",
        {"conflicts": conflicts},
        "Vérifier ECMP, distances administratives, VRF et intention de routage avant correction."))

    connected = defaultdict(list)
    for interface in interfaces:
        if not isinstance(interface, dict) or interface.get("admin_enabled") is False:
            continue
        vrf = str(interface.get("vrf") or "global")
        for addr in interface.get("ipv4_addresses") or []:
            net = _ipnet(addr.get("cidr"))
            if net:
                connected[vrf].append(net)
    unresolved = []
    for route in routes:
        if not isinstance(route, dict):
            continue
        hop = _ipaddr(route.get("next_hop"))
        if hop and hop.version == 4 and not route.get("outgoing_interface"):
            vrf = str(route.get("vrf") or "global")
            if not any(hop in net for net in connected[vrf]):
                unresolved.append({"prefix": route.get("prefix"),
                                   "next_hop": str(hop), "vrf": vrf,
                                   "source_line": _source(route)})
    findings.append(_finding("INVALID_DEFAULT_GATEWAY",
        "REVIEW" if unresolved else ("PASS" if routes else "UNKNOWN"),
        "HIGH", "Next-hop sans réseau directement connecté identifiable",
        {"unresolved_next_hops": unresolved},
        "Contrôler les routes récursives, interfaces, VRF et la table de routage réelle."))

    shadowed = []
    unsupported_acl_entries = 0
    for acl in acls:
        if not isinstance(acl, dict):
            continue
        previous = []
        for entry in acl.get("entries") or []:
            current = _shadowable(acl.get("type"), entry)
            if current:
                proto, src, dst = current
                for prior, earlier in previous:
                    pproto, psrc, pdst = prior
                    if (pproto in {"ip", proto} and
                            src.subnet_of(psrc) and dst.subnet_of(pdst)):
                        shadowed.append({"acl": acl.get("name"),
                                         "masked_line": _source(entry),
                                         "masking_line": _source(earlier)})
                        break
                previous.append((current, entry))
            elif entry.get("action") in {"permit", "deny"}:
                unsupported_acl_entries += 1
    findings.append(_finding("ACL_RULE_SHADOWING", "FAIL" if shadowed else
                             ("UNKNOWN" if unsupported_acl_entries else "PASS"),
        "MEDIUM", "Règles ACL entièrement masquées par une règle précédente",
        {"shadowed_rules": shadowed, "unmodeled_acl_entries": unsupported_acl_entries},
        "Examiner l'ordre des ACE et les intentions de filtrage avant réorganisation."))

    referenced = {str(binding.get("name")) for intf in interfaces if isinstance(intf, dict)
                  for binding in intf.get("acl_bindings") or []}
    for line in (ir.get("management") or {}).get("terminal_lines") or []:
        if isinstance(line, dict):
            for binding in line.get("access_classes") or []:
                if isinstance(binding, dict):
                    acl_name = binding.get("acl") or binding.get("name")
                    if acl_name:
                        referenced.add(str(acl_name))
    unused = [{"acl": acl.get("name"), "source_line": _source(acl)}
              for acl in acls if isinstance(acl, dict) and acl.get("name")
              and str(acl["name"]) not in referenced]
    findings.append(_finding("UNUSED_ACL", "REVIEW" if unused else "PASS", "LOW",
        "ACL sans liaison directe trouvée dans les interfaces / VTY modélisées",
        {"candidates": unused},
        "Vérifier les autres usages (route-map, NAT, QoS) avant toute suppression."))

    # Same-VRF overlap between DIFFERENT interfaces is suspicious, but can be
    # legitimate on secondary addresses, bridging or special architectures.
    overlaps = []
    interface_networks = []
    for interface in interfaces:
        if not isinstance(interface, dict) or interface.get("admin_enabled") is False:
            continue
        for address in interface.get("ipv4_addresses") or []:
            if not isinstance(address, dict):
                continue
            network = _ipnet(address.get("cidr"))
            if network and network.version == 4:
                interface_networks.append((str(interface.get("vrf") or "global"),
                                           str(interface.get("name") or "?"), network,
                                           _source(interface)))
    for i, (vrf, name, net, line) in enumerate(interface_networks):
        for other_vrf, other_name, other_net, other_line in interface_networks[i + 1:]:
            if name != other_name and vrf == other_vrf and net.overlaps(other_net):
                overlaps.append({"vrf": vrf, "interface_a": name,
                                 "interface_b": other_name, "subnet_a": str(net),
                                 "subnet_b": str(other_net),
                                 "source_lines": [line, other_line]})
    findings.append(_finding("OVERLAPPING_INTERFACE_SUBNETS",
        "REVIEW" if overlaps else ("PASS" if interface_networks else "UNKNOWN"),
        "HIGH", "Sous-réseaux IPv4 chevauchants sur plusieurs interfaces d'une même VRF",
        {"overlaps": overlaps},
        "Vérifier les adresses secondaires, le routage et l'architecture L2 avant modification."))

    # A reference to an undefined ACL cannot be classified FAIL unless the
    # operator explicitly declared the uploaded configuration complete.
    defined_acls = {str(acl.get("name")) for acl in acls
                    if isinstance(acl, dict) and acl.get("name")}
    missing_bindings = []
    for interface in interfaces:
        if not isinstance(interface, dict):
            continue
        for binding in interface.get("acl_bindings") or []:
            if not isinstance(binding, dict):
                continue
            name = binding.get("name")
            if name and str(name) not in defined_acls:
                missing_bindings.append({"acl": str(name), "interface": interface.get("name"),
                                         "direction": binding.get("direction"),
                                         "source_line": _source(interface)})
    findings.append(_finding("UNDEFINED_ACL_BINDING",
        ("FAIL" if complete_config else "REVIEW") if missing_bindings else "PASS",
        "HIGH", "Interfaces associées à une ACL absente de la configuration analysée",
        {"missing_bindings": missing_bindings, "completeness_required_for_fail": True},
        "Vérifier le nom de l'ACL, sa définition et la complétude du fichier avant correction."))

    dhcp_pools = ((ir.get("services") or {}).get("dhcp") or {}).get("pools") or []
    dhcp_overlaps = []
    for i, pool in enumerate(dhcp_pools):
        if not isinstance(pool, dict):
            continue
        network = _ipnet(pool.get("subnet"))
        if not network:
            continue
        for other in dhcp_pools[i + 1:]:
            if not isinstance(other, dict):
                continue
            other_network = _ipnet(other.get("subnet"))
            if other_network and network.version == other_network.version and network.overlaps(other_network):
                dhcp_overlaps.append({"pool_a": pool.get("name"), "pool_b": other.get("name"),
                                      "subnet_a": str(network), "subnet_b": str(other_network)})
    findings.append(_finding("OVERLAPPING_DHCP_POOLS", "REVIEW" if dhcp_overlaps else
                             ("PASS" if dhcp_pools else "NOT_APPLICABLE"),
        "MEDIUM", "Pools DHCP utilisant des plages réseau chevauchantes",
        {"overlaps": dhcp_overlaps},
        "Contrôler les exclusions, les VRF et le plan d'adressage DHCP."))

    # OSPF MD5: a configured digest mode without a local digest key is worth
    # review. Interface keying is not always modeled fully, hence no FAIL.
    ospf_processes = (ir.get("routing") or {}).get("ospf") or []
    ospf_suspects = []
    for process in ospf_processes:
        if not isinstance(process, dict):
            continue
        for interface in interfaces:
            if not isinstance(interface, dict):
                continue
            mode = str(interface.get("ospf_authentication_mode") or "").lower()
            if "message-digest" not in mode and mode != "md5":
                continue
            if interface.get("ospf_md5_key_ids"):
                continue
            # An OSPF process does not prove membership of this interface.
            # Keep the finding as REVIEW even when the process is configured.
            ospf_suspects.append({"process_id": process.get("process_id"),
                "interface": interface.get("name"), "source_line": _source(interface),
                "reason": "MD5 configuré sans clé MD5 modélisée sur l'interface"})
    findings.append(_finding("OSPF_MD5_KEY_COHERENCE",
        "REVIEW" if ospf_suspects else ("PASS" if ospf_processes else "NOT_APPLICABLE"),
        "HIGH", "Authentification OSPF MD5 sans clé identifiable",
        {"candidates": ospf_suspects},
        "Examiner les interfaces réellement participantes, l'héritage des zones et les key-chains avant correction."))

    # BGP remote-as is a syntactic range constraint. Reachability requires a
    # dynamic routing table and cannot be inferred from static routes alone.
    bgp_processes = (ir.get("routing") or {}).get("bgp") or []
    bgp_invalid = []
    bgp_remote = []
    for process in bgp_processes:
        if not isinstance(process, dict):
            continue
        for peer in process.get("neighbors") or []:
            if not isinstance(peer, dict) or peer.get("kind") == "peer_group":
                continue
            remote_as = peer.get("remote_as")
            if remote_as is not None and (type(remote_as) is not int or not 1 <= remote_as <= 4294967295):
                bgp_invalid.append({"peer": peer.get("id"), "remote_as": str(remote_as),
                                    "source_line": _source(peer)})
            elif remote_as is None:
                bgp_remote.append({"peer": peer.get("id"), "source_line": _source(peer)})
    findings.append(_finding("BGP_REMOTE_AS_COHERENCE",
        "FAIL" if bgp_invalid else ("REVIEW" if bgp_remote else
        ("PASS" if bgp_processes else "NOT_APPLICABLE")),
        "HIGH", "AS de voisin BGP absent ou hors plage valide",
        {"invalid_as": bgp_invalid, "missing_as": bgp_remote},
        "Valider la configuration effective du peer-group et l'AS distant avec l'opérateur."))

    # A remote peer beyond connected networks may be reached recursively via
    # IGP or another VRF. It is therefore REVIEW, not a reachability FAIL.
    bgp_unconfirmed = []
    connected_all = [net for nets in connected.values() for net in nets]
    for process in bgp_processes:
        if not isinstance(process, dict):
            continue
        for peer in process.get("neighbors") or []:
            if not isinstance(peer, dict) or peer.get("kind") == "peer_group":
                continue
            address = _ipaddr(peer.get("id"))
            if address and address.version == 4 and connected_all and not any(
                    address in net for net in connected_all):
                bgp_unconfirmed.append({"neighbor": str(address),
                                        "source_line": _source(peer),
                                        "update_source": peer.get("update_source")})
    findings.append(_finding("BGP_PEER_REACHABILITY",
        "REVIEW" if bgp_unconfirmed else ("NOT_APPLICABLE" if not bgp_processes else
        ("PASS" if connected_all else "UNKNOWN")),
        "MEDIUM", "Voisins BGP sans lien direct identifiable dans les interfaces locales",
        {"peers_to_verify": bgp_unconfirmed},
        "Vérifier la table de routage, les loopbacks, eBGP multihop, update-source et VRF sur l'équipement."))

    vlan_inventory = (ir.get("services") or {}).get("vlans") or []
    vlan_ids = {v.get("id") for v in vlan_inventory if isinstance(v, dict) and
                type(v.get("id")) is int}
    undefined_vlans = []
    for interface in interfaces:
        if not isinstance(interface, dict):
            continue
        switchport = interface.get("switchport") or {}
        if switchport.get("mode") != "access":
            continue
        access_vlan = switchport.get("access_vlan")
        if type(access_vlan) is int and access_vlan not in vlan_ids and access_vlan != 1:
            undefined_vlans.append({"interface": interface.get("name"),
                                    "vlan": access_vlan, "source_line": _source(interface)})
    findings.append(_finding("UNDECLARED_ACCESS_VLAN",
        ("FAIL" if complete_config and vlan_ids else "REVIEW") if undefined_vlans else
        ("PASS" if vlan_inventory else "NOT_APPLICABLE"),
        "MEDIUM", "VLAN d'accès absent de l'inventaire VLAN local",
        {"undefined_access_vlans": undefined_vlans, "declared_vlans": sorted(vlan_ids)},
        "Vérifier VTP, les VLAN appris à distance et la base VLAN opérationnelle avant création."))

    nat_rules = ((ir.get("services") or {}).get("nat") or {}).get("rules") or []
    static_globals = defaultdict(list)
    for rule in nat_rules:
        if not isinstance(rule, dict) or not rule.get("inside_local") or not rule.get("inside_global"):
            continue
        # Only exact address-only static mappings are comparable here; PAT
        # on different ports legitimately reuses a public address.
        if rule.get("protocol") or rule.get("inside_port") is not None or rule.get("outside_port") is not None:
            continue
        global_ip = _ipaddr(rule["inside_global"])
        local_ip = _ipaddr(rule["inside_local"])
        if global_ip and local_ip:
            static_globals[str(global_ip)].append((str(local_ip), _source(rule)))
    nat_collisions = []
    for global_ip, mappings in static_globals.items():
        if len({address for address, _ in mappings}) > 1:
            nat_collisions.append({"inside_global": global_ip,
                "inside_locals": sorted({address for address, _ in mappings}),
                "source_lines": [line for _, line in mappings]})
    findings.append(_finding("NAT_STATIC_GLOBAL_COLLISION",
        "FAIL" if nat_collisions else ("PASS" if nat_rules else "NOT_APPLICABLE"),
        "HIGH", "Plusieurs IP internes associées à la même IP globale par NAT statique 1:1",
        {"collisions": nat_collisions},
        "Attribuer une IP globale distincte à chaque translation statique 1:1 ; vérifier les translations existantes."))

    return {"engine": "network_coherence_v3", "static_only": True,
            "complete_config_assumed": complete_config, "findings": findings}
