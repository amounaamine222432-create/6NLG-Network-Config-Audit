"""Adaptateur d'AST Junos issu de bibliothèques externes vers IR v1.

Ce module NE PARSE PAS la syntaxe Junos : les relations parent/enfant viennent
de ciscoconfparse2 (accolades) ou de clijson (display set). Il traduit un
sous-ensemble explicite. Tout élément non transposé reste comptabilisé.

La représentation est une analyse de configuration, jamais un état opérationnel.
"""

from __future__ import annotations

from collections import Counter
import hashlib
from importlib.metadata import version as package_version
import ipaddress
from pathlib import Path
import re
from typing import Any

from normalizers.junos_tree_loader import is_junos_comment_node, load_junos_tree


SCHEMA_VERSION = "1.0.0"
SAFE_SECTIONS = {"system", "interfaces", "protocols", "routing-options",
                 "routing-instances", "policy-options", "security", "vlans",
                 "switch-options", "forwarding-options", "chassis", "firewall",
                 "services", "snmp"}
KNOWN_FAMILIES = {"inet", "inet6", "evpn", "inet-vpn", "l2vpn", "iso"}
TAXONOMY_TOKENS = {
    "policy-options", "protocols", "policy-statement", "term", "from", "then",
    "route-filter", "protocol", "community", "members", "prefix-list", "as-path",
    "accept", "reject", "next-hop", "local-preference", "metric", "preference",
    "as-path-prepend", "add", "delete", "set", "load-balance", "tag",
    "bgp", "ospf", "evpn", "lldp", "isis", "mpls", "ldp", "rsvp",
    "group", "neighbor", "family", "unicast", "signaling", "multipath",
    "local-as", "peer-as", "type", "import", "export", "graceful-restart",
    "bfd-liveness-detection", "minimum-interval", "multiplier", "session-mode",
    "mtu-discovery", "log-updown", "vpn-apply-export", "local-address",
    "route-reflector-client", "cluster", "authentication-key", "interface",
    "area", "traffic-engineering", "reference-bandwidth", "port-id-subtype",
    "encapsulation", "default-gateway", "extended-vni-list", "interface-mode",
    "routing-instances", "security", "interfaces", "routing-options", "switch-options",
    "forwarding-options", "vlan", "vlan-id", "vni", "vxlan", "rib",
    "ip-prefix-routes", "irb-symmetric-routing", "advertise", "vrf-import",
    "vrf-export", "vrf-table-label", "auto-export", "system",
}


def _text(node: Any) -> str:
    return node.text.strip()


def _parts(node: Any) -> list[str]:
    return _text(node).split()


def _children(node: Any, prefix: str | None = None) -> list[Any]:
    result = list(getattr(node, "children", []) or [])
    if prefix is None:
        return result
    return [c for c in result if _text(c) == prefix or _text(c).startswith(prefix + " ")]


def _child(node: Any, prefix: str) -> Any | None:
    return next(iter(_children(node, prefix)), None)


def _value(node: Any, prefix: str) -> str | None:
    candidate = _child(node, prefix)
    if candidate is None:
        return None
    return _text(candidate)[len(prefix):].strip().strip('"') or None


def _int(value: str | None) -> int | None:
    if value is None or not re.fullmatch(r"\d+", value):
        return None
    return int(value)


def _ref(_: Any = None) -> dict[str, None]:
    # Aucun des deux AST externes ne garantit une ligne physique originale.
    return {"line": None}


def _empty_ir(path: Path, version: str | None) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "source": {
            "vendor": "juniper_junos", "parser_schema_version": f"ciscoconfparse2-{package_version('ciscoconfparse2')}",
            "file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        },
        "device": {"hostname": None, "platform": {
            "vendor": "juniper", "family": "junos", "version": version,
        }},
        "vrfs": [], "interfaces": [],
        "routing": {"static_routes": [], "ospf": [], "bgp": []},
        "policies": {"acls": [], "prefix_lists": [], "route_maps": [], "community_lists": []},
        "services": {"nat": {"rules": [], "pools": []},
                     "dhcp": {"pools": [], "excluded_ranges": []},
                     "vlans": [], "snmp": {"communities": [], "targets": []},
                     "syslog": {"targets": [], "source_interface": None, "severity": None}},
        "management": {"http_enabled": None, "https_enabled": None,
                       "ssh_version": None, "terminal_lines": [],
                       "local_accounts": [], "banners": []},
        "diagnostics": {"unparsed_global_count": 0, "unparsed_global_lines": [],
                        "platform_opaque_count": 0, "opaque_sections": [],
                        "source_only_counts": {}, "notes": [], "status": "partial"},
    }


def _iter_descendants(node: Any):
    for child in _children(node):
        yield child
        yield from _iter_descendants(child)


def _safe_taxonomy(node: Any) -> str:
    """Signatures sans valeurs/identifiants : aucun secret, IP ou nom métier."""
    hierarchy = [node]
    while hierarchy[-1].parent is not hierarchy[-1]:
        hierarchy.append(hierarchy[-1].parent)
    labels = []
    for ancestor in reversed(hierarchy):
        tokens = _parts(ancestor)
        keyword = tokens[0] if tokens else ""
        if keyword == "family" and len(tokens) > 1 and tokens[1] in KNOWN_FAMILIES:
            labels.append(f"family:{tokens[1]}")
        else:
            labels.append(keyword if keyword in TAXONOMY_TOKENS else "other")
    return ".".join(labels)


class _Coverage:
    def __init__(self) -> None:
        self.marked: set[int] = set()
        self.notes: set[str] = set()

    def take(self, *nodes: Any) -> None:
        for node in nodes:
            if node is not None:
                self.marked.add(id(node))

    def flag(self, message: str) -> None:
        self.notes.add(message)


def _families(node: Any, coverage: _Coverage) -> list[str]:
    result = []
    for family in _children(node, "family"):
        coverage.take(family)
        # Junos : « family inet { unicast; } », l'AF est dans le NOM du
        # parent, et non dans ses enfants.
        tokens = _parts(family)
        if len(tokens) >= 2 and tokens[1] in KNOWN_FAMILIES:
            result.append(tokens[1])
            coverage.take(_child(family, "unicast"), _child(family, "signaling"))
    return sorted(set(result))


def _ipv4(value: str) -> tuple[str, int, str] | None:
    try:
        address = ipaddress.IPv4Interface(value)
        return str(address.ip), address.network.prefixlen, str(address)
    except ValueError:
        return None


def _route_entries(options: Any, vrf: str | None, ir: dict, cov: _Coverage) -> None:
    static = _child(options, "static")
    if static is None:
        return
    cov.take(static)
    for route in _children(static, "route"):
        cov.take(route)
        parts = _parts(route)
        if len(parts) < 2:
            cov.flag("Une route statique ne fournit pas de préfixe utilisable.")
            continue
        try:
            network = ipaddress.IPv4Network(parts[1], strict=False)
        except ValueError:
            cov.flag("Certaines routes statiques IPv6 ou invalides ne sont pas représentables par cet adaptateur IPv4.")
            continue
        # Une route Junos peut être une feuille sur UNE ligne :
        # « route 0.0.0.0/0 next-hop 10.0.0.2; ».
        # Ou un bloc : « route 0.0.0.0/0 { next-hop ...; preference ...; } ».
        inline = parts[2:]
        inline_hop = (inline[inline.index("next-hop") + 1]
                      if "next-hop" in inline and inline.index("next-hop") + 1 < len(inline) else None)
        hop = _value(route, "next-hop") or inline_hop
        # Junos peut encoder les actions de rejet / discard dans la route.
        action = next((x for x in ("discard", "reject")
                       if x in inline or _child(route, x)), None)
        outgoing = None
        if hop and re.fullmatch(r"[a-z]{1,8}[a-z0-9-]*[0-9][\w./:-]*", hop):
            try:
                ipaddress.ip_address(hop)
            except ValueError:
                outgoing, hop = hop, None
        if _child(route, "next-hop"):
            cov.take(_child(route, "next-hop"))
        if action:
            cov.take(_child(route, action))
        entry = {
            "prefix": str(network), "vrf": vrf, "next_hop": hop,
            "outgoing_interface": outgoing, "administrative_distance": None,
            "junos_action": action, "unmodeled_option_count": 0,
            "source": _ref(route),
        }
        # `preference` ≠ distance administrative Cisco, valeur conservée séparément.
        inline_preference = (inline[inline.index("preference") + 1]
                             if "preference" in inline and inline.index("preference") + 1 < len(inline) else None)
        preference = _int(_value(route, "preference") or inline_preference)
        if preference is not None:
            entry["junos_preference"] = preference
            cov.take(_child(route, "preference"))
        if not hop and not outgoing and not action:
            cov.flag("Certaines routes statiques nécessitent une analyse d'options Junos supplémentaire.")
        known_inline = {"next-hop", "discard", "reject", "preference", inline_hop, inline_preference}
        unknown_inline = [token for token in inline if token not in known_inline]
        if unknown_inline:
            entry["unmodeled_option_count"] = len(unknown_inline)
            cov.flag("Des options de routes statiques Junos ne sont pas entièrement normalisées.")
            cov.marked.discard(id(route))
        ir["routing"]["static_routes"].append(entry)


def _interfaces(section: Any, assignments: dict[str, str], ir: dict, cov: _Coverage) -> None:
    cov.take(section)
    for physical in _children(section):
        tokens = _parts(physical)
        if len(tokens) != 1 or tokens[0] in {"interface-range", "apply-groups"}:
            continue
        name = tokens[0]
        cov.take(physical)
        disabled = _child(physical, "disable") is not None
        cov.take(_child(physical, "disable"))
        desc = _child(physical, "description")
        cov.take(desc)
        mtu = _int(_value(physical, "mtu"))
        cov.take(_child(physical, "mtu"))
        if desc:
            cov.flag("Texte libre des descriptions d'interface omis de l'IR par précaution de confidentialité.")
        for unit in _children(physical, "unit"):
            parts = _parts(unit)
            if len(parts) != 2:
                continue
            cov.take(unit)
            logical = f"{name}.{parts[1]}"
            ips = []
            is_dhcp = False
            vlan_id = _int(_value(unit, "vlan-id"))
            cov.take(_child(unit, "vlan-id"))
            for family in _children(unit, "family"):
                cov.take(family)
                if _text(family) == "family inet":
                    for leaf in _children(family):
                        if _text(leaf) == "dhcp":
                            cov.take(leaf)
                            is_dhcp = True
                        elif _text(leaf).startswith("address "):
                            cov.take(leaf)
                            address = _ipv4(_text(leaf)[len("address "):])
                            if address:
                                ips.append({"address": address[0], "prefix_length": address[1],
                                            "cidr": address[2], "secondary": False})
                            else:
                                cov.flag("Une adresse IPv4 d'interface est invalide et a été ignorée.")
            cov.take(_child(unit, "disable"), _child(unit, "description"))
            admin = False if disabled or _child(unit, "disable") else None
            ir["interfaces"].append({
                "name": logical, "description": None, "description_configured": bool(desc or _child(unit, "description")),
                "admin_enabled": admin, "operational_state": None,
                "link": {"mtu": mtu}, "ipv4_addresses": ips,
                "ipv4_dhcp": is_dhcp, "ipv4_explicitly_absent": False,
                "vrf": assignments.get(logical), "nat_role": None,
                "dhcp_relay_targets": [], "vlan_tagging": ({"vlan_id": vlan_id, "native": False}
                                                           if vlan_id is not None else None),
                "hsrp_groups": [], "source": _ref(unit),
            })


def _routing_instances(section: Any, ir: dict, cov: _Coverage) -> dict[str, str]:
    cov.take(section)
    assignments: dict[str, str] = {}
    for inst in _children(section):
        name = _text(inst)
        cov.take(inst)
        type_of_instance = _value(inst, "instance-type")
        cov.take(_child(inst, "instance-type"))
        if not type_of_instance:
            type_of_instance = "unspecified"
        for interface in _children(inst, "interface"):
            cov.take(interface)
            parts = _parts(interface)
            if len(parts) >= 2:
                assignments[parts[1]] = name
        route_target = _value(inst, "vrf-target")
        rd = _value(inst, "route-distinguisher")
        cov.take(_child(inst, "vrf-target"), _child(inst, "route-distinguisher"))
        route_targets = ([{"direction": "both", "target": route_target}] if route_target else [])
        afs = []
        inst_protocols = _child(inst, "protocols")
        if inst_protocols:
            cov.take(inst_protocols)
            if _child(inst_protocols, "evpn"):
                afs.append("evpn")
        ir["vrfs"].append({"name": name, "route_distinguisher": rd,
                           "address_families": afs, "route_targets": route_targets,
                           "junos_instance_type": type_of_instance,
                           "source": _ref(inst)})
        if type_of_instance not in ("vrf", "virtual-router"):
            cov.flag("Certaines routing-instances Junos ne sont pas des VRF (ex. mgmt_junos) : leur type est conservé.")
        for options in _children(inst, "routing-options"):
            cov.take(options)
            _route_entries(options, name, ir, cov)
    return assignments


def _bgp(protos: Any, options: Any | None, ir: dict, cov: _Coverage) -> None:
    bgp = _child(protos, "bgp")
    if bgp is None:
        return
    cov.take(bgp)
    global_as = _int(_value(options, "autonomous-system")) if options else None
    rid = _value(options, "router-id") if options else None
    for group in _children(bgp, "group"):
        fields = _parts(group)
        if len(fields) != 2:
            continue
        group_name = fields[1]
        cov.take(group)
        local_as = _int(_value(group, "local-as"))
        if local_as is None:
            local_as = global_as
        group_peer_as = _int(_value(group, "peer-as"))
        group_families = _families(group, cov)
        mode = _value(group, "type")
        session = {"external": "ebgp", "internal": "ibgp"}.get(mode)
        local_address = _value(group, "local-address")
        cov.take(_child(group, "local-as"), _child(group, "peer-as"),
                 _child(group, "type"), _child(group, "local-address"))
        policies = []
        for direction in ("import", "export"):
            for policy in _children(group, direction):
                cov.take(policy)
                policies.append({"policy_name": _text(policy)[len(direction):].strip(),
                                 "direction": "in" if direction == "import" else "out",
                                 "source": _ref(policy)})
        peers = []
        for peer in _children(group, "neighbor"):
            fields = _parts(peer)
            if len(fields) != 2:
                continue
            cov.take(peer)
            remote_as = _int(_value(peer, "peer-as"))
            cov.take(_child(peer, "peer-as"), _child(peer, "description"),
                     _child(peer, "local-address"))
            peers.append({
                "id": fields[1], "kind": "peer", "peer_group": group_name,
                "remote_as": remote_as if remote_as is not None else group_peer_as,
                "session_type_configured": session,
                "activated_families": group_families,
                "update_source": _value(peer, "local-address") or local_address,
                "description_configured": _child(peer, "description") is not None,
                "description_source": _ref(peer) if _child(peer, "description") else None,
                "policies": policies, "source": _ref(peer),
            })
        ir["routing"]["bgp"].append({
            "local_as": local_as, "router_id": rid,
            "neighbors": peers, "network_statements": [],
            "address_families": group_families,
            "junos_group": group_name, "source": _ref(group),
        })
    if len(_children(bgp, "group")) > 1:
        cov.flag("Junos BGP est représenté ici par groupe (ASN local potentiellement différent), et NON par processus Cisco.")


def _ospf(protos: Any, options: Any | None, ir: dict, cov: _Coverage) -> None:
    ospf = _child(protos, "ospf")
    if ospf is None:
        return
    cov.take(ospf)
    by_area: list[dict[str, Any]] = []
    passive = []
    for area in _children(ospf, "area"):
        fields = _parts(area)
        if len(fields) != 2:
            continue
        cov.take(area)
        interfaces = []
        for interface in _children(area, "interface"):
            iparts = _parts(interface)
            if len(iparts) != 2:
                continue
            cov.take(interface)
            interfaces.append(iparts[1])
            if _child(interface, "passive"):
                passive.append(iparts[1])
                cov.take(_child(interface, "passive"))
        by_area.append({"area": fields[1], "interfaces": interfaces})
    ir["routing"]["ospf"].append({
        # Aucun numéro de processus OSPF Cisco n'existe dans cette syntaxe.
        "process_id": "", "process_id_applicability": "not_applicable_junos",
        "router_id": _value(options, "router-id") if options else None,
        "network_selectors": [], "passive_interfaces": passive,
        "junos_interfaces_by_area": by_area,
        "source": _ref(ospf),
    })
    cov.flag("OSPF Junos : process_id Cisco non applicable (chaîne vide documentée), interfaces/aires exposées dans une extension IR v1.")


def normalize_juniper_junos(
    source_file: str | Path, *, unmodeled_inventory: Counter[str] | None = None,
    _parsed: Any | None = None, _modeled_node_ids: set[int] | None = None,
) -> dict[str, Any]:
    """Normalise l'AST externe ciscoconfparse2 (accolades) ou clijson (set)."""

    path = Path(source_file)
    parser = _parsed if _parsed is not None else load_junos_tree(path)
    roots = [n for n in parser.config_objs if n.parent is n and not is_junos_comment_node(n)]
    root_by_name = {(_parts(n) or [""])[0]: n for n in roots}
    version = next((_text(n).split(" ", 1)[1] for n in roots if _text(n).startswith("version ")), None)
    ir = _empty_ir(path, version)
    if parser.format == "display_set":
        ir["source"]["parser_schema_version"] = "clijson-" + package_version("clijson")
    cov = _Coverage()
    for n in roots:
        if _text(n).startswith("version "):
            cov.take(n)
    system = root_by_name.get("system")
    if system:
        cov.take(system)
        hostname = _value(system, "host-name")
        if hostname and not (hostname.startswith("<") and hostname.endswith(">")):
            ir["device"]["hostname"] = hostname
            cov.take(_child(system, "host-name"))
        elif hostname:
            cov.flag("Nom d'hôte non conclu : champ de substitution dans un modèle de configuration.")

    options = root_by_name.get("routing-options")
    if options:
        cov.take(options, _child(options, "autonomous-system"), _child(options, "router-id"))
        _route_entries(options, None, ir, cov)

    assignments: dict[str, str] = {}
    instances = root_by_name.get("routing-instances")
    if instances:
        assignments = _routing_instances(instances, ir, cov)
    interface_root = root_by_name.get("interfaces")
    if interface_root:
        _interfaces(interface_root, assignments, ir, cov)

    protocols = root_by_name.get("protocols")
    if protocols:
        cov.take(protocols)
        _bgp(protocols, options, ir, cov)
        _ospf(protocols, options, ir, cov)

    vlans = root_by_name.get("vlans")
    if vlans:
        cov.take(vlans)
        for vlan in _children(vlans):
            cov.take(vlan)
            number = _int(_value(vlan, "vlan-id"))
            l3 = _value(vlan, "l3-interface")
            vxlan = _child(vlan, "vxlan")
            vni = _int(_value(vxlan, "vni")) if vxlan else None
            cov.take(_child(vlan, "vlan-id"), _child(vlan, "l3-interface"),
                     vxlan, _child(vxlan, "vni") if vxlan else None)
            ir["services"]["vlans"].append({
                "name": _text(vlan), "vlan_id": number,
                "l3_interface": l3, "junos_vxlan_vni": vni,
                "source": _ref(vlan),
            })

    # Comptabiliser toutes les feuilles non prises en charge, sans en publier
    # le contenu (mots de passe, clés, communautés SNMP, etc.).
    unmodeled: Counter[str] = Counter()
    total_leaves = 0
    modeled_leaves = 0
    for node in parser.config_objs:
        if _children(node) or not _text(node) or is_junos_comment_node(node):
            continue
        total_leaves += 1
        if id(node) in cov.marked:
            modeled_leaves += 1
        else:
            root = node
            while root.parent is not root:
                root = root.parent
            section = (_parts(root) or ["other"])[0]
            unmodeled[section if section in SAFE_SECTIONS else "other"] += 1
            if unmodeled_inventory is not None:
                unmodeled_inventory[_safe_taxonomy(node)] += 1
    notes = sorted(cov.notes)
    notes.extend(parser.warnings)
    notes.append("IR fondée sur la configuration statique : aucune validation d'état opérationnel.")
    notes.append("Les numéros de ligne physiques ne sont pas garantis par ciscoconfparse2 Junos ; source.line=null.")
    if unmodeled:
        notes.append("Les feuilles non transposées restent comptées par section, sans exporter les commandes ni leurs secrets.")
    diag = ir["diagnostics"]
    diag["opaque_sections"] = [
        {"section": section, "count": count, "source": {"line": None}}
        for section, count in sorted(unmodeled.items())
    ]
    diag["platform_opaque_count"] = sum(unmodeled.values())
    diag["unparsed_global_count"] = unmodeled.get("global", 0)
    diag["source_only_counts"] = {
        "parser_objects": len(parser.config_objs),
        "config_leaves": total_leaves,
        "normalized_leaves": modeled_leaves,
        "unmodeled_leaves": sum(unmodeled.values()),
        "bgp_groups": len(ir["routing"]["bgp"]),
        "ospf_instances": len(ir["routing"]["ospf"]),
        "interfaces_logical": len(ir["interfaces"]),
    }
    diag["notes"] = notes
    if _modeled_node_ids is not None:
        _modeled_node_ids.update(cov.marked)
    # Une représentation partielle est assumée dès qu'il reste des feuilles
    # non modélisées ou des écarts sémantiques structurels.
    diag["status"] = "partial" if unmodeled or cov.notes else "modeled_subset"
    return ir
