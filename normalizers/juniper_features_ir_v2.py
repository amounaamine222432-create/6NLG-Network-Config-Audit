"""Projection additive et conservatrice d'une configuration Junos vers IR v2.

L'arbre est produit par ciscoconfparse2 (accolades) ou clijson (display set)
via l'adaptateur commun. Ce module n'est PAS un parseur Junos. Il traduit des formes connues
vers des propriétés de configuration (jamais vers un état opérationnel).

Les secrets et descriptions libres ne sont jamais exportés. Les feuilles non
interprétées restent comptabilisées, avec une taxonomie sans valeur brute.
"""

from __future__ import annotations

from collections import Counter
import ipaddress
from pathlib import Path
import re
from typing import Any

from normalizers.junos_tree_loader import is_junos_comment_node, load_junos_tree


def _t(node: Any) -> list[str]:
    return node.text.strip().split()


def _ch(node: Any | None, key: str | None = None) -> list[Any]:
    if node is None:
        return []
    children = list(node.children)
    if key is None:
        return children
    return [c for c in children if _t(c) and _t(c)[0] == key]


def _first(node: Any | None, key: str) -> Any | None:
    return next(iter(_ch(node, key)), None)


def _val(node: Any | None, key: str) -> str | None:
    child = _first(node, key)
    t = _t(child) if child else []
    return t[1] if len(t) == 2 else None


def _integer(value: str | None, *, low: int = 0, high: int = 2**32 - 1) -> int | None:
    if value is not None and value.isascii() and value.isdecimal():
        number = int(value)
        return number if low <= number <= high else None
    return None


def _ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _prefix(value: str) -> str | None:
    try:
        return str(ipaddress.ip_interface(value))
    except ValueError:
        return None


class _Visitor:
    def __init__(self, parser: Any):
        self.parser = parser
        self.accepted: set[int] = set()

    def take(self, node: Any | None) -> None:
        if node is not None:
            self.accepted.add(id(node))

    def flag(self, node: Any | None, text: str) -> bool:
        if node is not None and _t(node) == text.split():
            self.take(node)
            return True
        return False

    def value(self, node: Any, key: str, *, allowed: set[str] | None = None) -> str | None:
        candidate = _first(node, key)
        result = _val(node, key)
        if result is not None and (allowed is None or result in allowed):
            self.take(candidate)
            return result
        return None

    def integer(self, node: Any, key: str, *, low: int = 0,
                high: int = 2**32 - 1) -> int | None:
        candidate = _first(node, key)
        number = _integer(_val(node, key), low=low, high=high)
        if number is not None:
            self.take(candidate)
        return number

    def _bfd(self, parent: Any) -> dict[str, Any] | None:
        node = _first(parent, "bfd-liveness-detection")
        if node is None:
            return None
        result = {}
        interval = self.integer(node, "minimum-interval", low=1, high=255000)
        multiplier = self.integer(node, "multiplier", low=1, high=255)
        mode = self.value(node, "session-mode", allowed={"single-hop", "multihop"})
        if interval is not None:
            result["minimum_interval_ms"] = interval
        if multiplier is not None:
            result["multiplier"] = multiplier
        if mode is not None:
            result["session_mode"] = mode
        if result:
            self.take(node)
        return result or None

    def _interface_entries(self, node: Any, *, nested: bool = False) -> list[dict[str, Any]]:
        result = []
        for item in _ch(node, "interface"):
            parts = _t(item)
            if len(parts) != 2:
                continue
            entry = {"name": parts[1]}
            if nested:
                if self.flag(_first(item, "passive"), "passive"):
                    entry["passive_configured"] = True
                bfd = self._bfd(item)
                if bfd:
                    entry["bfd"] = bfd
                for key, low, high in (("metric", 0, 65535), ("priority", 0, 255),
                                       ("hello-interval", 1, 65535), ("dead-interval", 1, 65535)):
                    number = self.integer(item, key, low=low, high=high)
                    if number is not None:
                        entry[key.replace("-", "_")] = number
                network_type = self.value(item, "interface-type", allowed={"p2p", "p2mp", "broadcast", "nbma"})
                if network_type:
                    entry["network_type"] = network_type
                auth = _first(item, "authentication")
                if auth:
                    for method in _ch(auth, "md5"):
                        tok = _t(method)
                        if len(tok) >= 4 and tok[2] == "key":
                            entry["authentication"] = {"type": "md5", "secret_redacted": True}
                            self.take(auth)
                            self.take(method)
            self.take(item)
            result.append(entry)
        return result

    def _protocols(self, protocols: Any | None) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if protocols is None:
            return result

        bgp = _first(protocols, "bgp")
        if bgp:
            data: dict[str, Any] = {"groups": []}
            for name, key in (("log_updown_configured", "log-updown"),
                              ("graceful_restart_configured", "graceful-restart")):
                if self.flag(_first(bgp, key), key):
                    data[name] = True
            for group in _ch(bgp, "group"):
                parts = _t(group)
                if len(parts) != 2:
                    continue
                entry: dict[str, Any] = {"name": parts[1]}
                for direction in ("import", "export"):
                    names: list[str] = []
                    for ref in _ch(group, direction):
                        fields = [x for x in _t(ref)[1:] if x not in ("[", "]")]
                        if fields and all(re.fullmatch(r"[A-Za-z0-9_.:/-]+", x) for x in fields):
                            names.extend(fields)
                            self.take(ref)
                    if names:
                        entry[direction + "_policies"] = names
                for output, key in (("mtu_discovery_configured", "mtu-discovery"),
                                    ("vpn_apply_export_configured", "vpn-apply-export")):
                    if self.flag(_first(group, key), key):
                        entry[output] = True
                preference = self.integer(group, "preference", low=0, high=255)
                if preference is not None:
                    entry["preference"] = preference
                hold = self.integer(group, "hold-time", low=3, high=65535)
                if hold is not None:
                    entry["hold_time_seconds"] = hold
                for key in ("remove-private", "as-override", "advertise-peer-as"):
                    if self.flag(_first(group, key), key):
                        entry[key.replace("-", "_") + "_configured"] = True
                auth = _first(group, "authentication-key")
                if auth and len(_t(auth)) >= 2:
                    entry["authentication_configured"] = True
                    entry["authentication_secret_redacted"] = True
                    self.take(auth)
                cluster = self.value(group, "cluster")
                if cluster:
                    entry["cluster_id"] = cluster
                multipath = _first(group, "multipath")
                if multipath and _t(multipath) == ["multipath"]:
                    entry["multipath_configured"] = True
                    self.take(multipath)
                    if self.flag(_first(multipath, "multiple-as"), "multiple-as"):
                        entry["multiple_as_configured"] = True
                bfd = self._bfd(group)
                if bfd:
                    entry["bfd"] = bfd
                neighbor_entries = []
                for peer in _ch(group, "neighbor"):
                    fields = _t(peer)
                    if len(fields) != 2:
                        continue
                    peer_options: dict[str, Any] = {"id": fields[1]}
                    peer_hold = self.integer(peer, "hold-time", low=3, high=65535)
                    if peer_hold is not None:
                        peer_options["hold_time_seconds"] = peer_hold
                    if self.flag(_first(peer, "disable"), "disable"):
                        peer_options["disabled_configured"] = True
                    peer_bfd = self._bfd(peer)
                    if peer_bfd:
                        peer_options["bfd"] = peer_bfd
                    peer_auth = _first(peer, "authentication-key")
                    if peer_auth and len(_t(peer_auth)) >= 2:
                        peer_options["authentication_configured"] = True
                        peer_options["authentication_secret_redacted"] = True
                        self.take(peer_auth)
                    if len(peer_options) > 1:
                        neighbor_entries.append(peer_options)
                if neighbor_entries:
                    entry["neighbors"] = neighbor_entries
                # Les options BGP déjà converties en IR v1 sont conservées
                # séparément. Aucune déduction d'adjacence ne se fait ici.
                data["groups"].append(entry)
            result["bgp"] = data

        ospf = _first(protocols, "ospf")
        if ospf:
            data = {"areas": []}
            for key in ("export", "import"):
                refs = []
                for policy in _ch(ospf, key):
                    tokens = [t for t in _t(policy)[1:] if t not in ("[", "]")]
                    if tokens and all(re.fullmatch(r"[\w./:-]+", p) for p in tokens):
                        refs.extend(tokens)
                        self.take(policy)
                if refs:
                    data[key + "_policies"] = refs
            if self.flag(_first(ospf, "traffic-engineering"), "traffic-engineering"):
                data["traffic_engineering_configured"] = True
            bw = self.value(ospf, "reference-bandwidth")
            if bw and re.fullmatch(r"[0-9]+(?:[kKmMgGtT])?", bw):
                data["reference_bandwidth_configured"] = bw
            else:
                # Ne pas compter comme reconnu si une forme inattendue passe.
                node = _first(ospf, "reference-bandwidth")
                if node is not None:
                    self.accepted.discard(id(node))
            for area in _ch(ospf, "area"):
                parts = _t(area)
                if len(parts) != 2:
                    continue
                area_data: dict[str, Any] = {"id": parts[1], "interfaces": self._interface_entries(area, nested=True)}
                for kind in ("stub", "nssa"):
                    kind_node = _first(area, kind)
                    if kind_node and _t(kind_node) == [kind]:
                        area_data["area_type"] = kind
                        self.take(kind_node)
                        if self.flag(_first(kind_node, "no-summaries"), "no-summaries"):
                            area_data["no_summaries_configured"] = True
                data["areas"].append(area_data)
            result["ospf"] = data

        isis = _first(protocols, "isis")
        if isis:
            data = {"interfaces": self._interface_entries(isis, nested=True), "disabled_levels": []}
            for level in _ch(isis, "level"):
                parts = _t(level)
                if len(parts) == 3 and parts[1] in ("1", "2") and parts[2] == "disable":
                    data["disabled_levels"].append(int(parts[1]))
                    self.take(level)
            result["isis"] = data

        for proto in ("rsvp", "ldp", "mpls", "lldp"):
            node = _first(protocols, proto)
            if node is None:
                continue
            data = {"interfaces": self._interface_entries(node)}
            if proto == "ldp" and self.flag(_first(node, "make-before-break"), "make-before-break"):
                data["make_before_break_configured"] = True
            if proto == "lldp":
                subtype = self.value(node, "port-id-subtype", allowed={"interface-name", "locally-assigned"})
                if subtype:
                    data["port_id_subtype"] = subtype
            if proto == "mpls":
                engineering = self.value(node, "traffic-engineering", allowed={"bgp", "bgp-igp"})
                if engineering:
                    data["traffic_engineering_mode"] = engineering
                for key in ("ipv6-tunneling", "no-decrement-ttl", "record"):
                    if self.flag(_first(node, key), key):
                        data[key.replace("-", "_") + "_configured"] = True
                paths = []
                for lsp in _ch(node, "label-switched-path"):
                    lp = _t(lsp)
                    if len(lp) != 2:
                        continue
                    target = self.value(lsp, "to")
                    if target is None or _ip(target) is None:
                        continue
                    item: dict[str, Any] = {"name": lp[1], "destination": _ip(target)}
                    if self.flag(_first(lsp, "fast-reroute"), "fast-reroute"):
                        item["fast_reroute_configured"] = True
                    self.take(lsp)
                    paths.append(item)
                data["label_switched_paths"] = paths
            result[proto] = data

        evpn = _first(protocols, "evpn")
        if evpn:
            data = {}
            encap = self.value(evpn, "encapsulation", allowed={"vxlan", "mpls", "srv6"})
            if encap:
                data["encapsulation"] = encap
            gateway = self.value(evpn, "default-gateway", allowed={"no-gateway-community", "do-not-advertise"})
            if gateway:
                data["default_gateway_option"] = gateway
            vnis = _first(evpn, "extended-vni-list")
            if vnis:
                tokens = _t(vnis)
                if len(tokens) == 2 and tokens[1] == "all":
                    data["extended_vni_list"] = {"all": True, "items": []}
                    self.take(vnis)
                elif len(tokens) >= 2 and all(re.fullmatch(r"[0-9]+(?:-[0-9]+)?", x)
                                                   for x in tokens[1:] if x not in ("[", "]")):
                    data["extended_vni_list"] = {"all": False,
                                                 "items": [x for x in tokens[1:] if x not in ("[", "]")]}
                    self.take(vnis)
            result["evpn"] = data
        stp = _first(protocols, "stp")
        if self.flag(stp, "stp") or self.flag(protocols, "protocols stp"):
            result["stp"] = {"configured": True}
        return result

    def _routing_instances(self, root: Any | None) -> list[dict[str, Any]]:
        results = []
        for inst in _ch(root):
            parts = _t(inst)
            if len(parts) != 1:
                continue
            entry: dict[str, Any] = {"name": parts[0]}
            instance_type = self.value(inst, "instance-type")
            if instance_type in {"vrf", "virtual-router", "evpn", "mac-vrf", "vpls", "forwarding", "no-forwarding"}:
                entry["instance_type"] = instance_type
            interfaces = []
            for interface in _ch(inst, "interface"):
                tokens = _t(interface)
                if len(tokens) == 2:
                    interfaces.append(tokens[1])
                    self.take(interface)
            if interfaces:
                entry["interfaces"] = interfaces
            target = self.value(inst, "vrf-target")
            if target and re.fullmatch(r"target:\d+:\d+", target):
                entry["vrf_target"] = target
            rd = self.value(inst, "route-distinguisher")
            if rd and re.fullmatch(r"[A-Za-z0-9.:]+:[0-9]+", rd):
                entry["route_distinguisher"] = rd
            for key in ("vrf-import", "vrf-export"):
                value = self.value(inst, key)
                if value:
                    entry[key.replace("-", "_")] = value
            if self.flag(_first(inst, "vrf-table-label"), "vrf-table-label"):
                entry["vrf_table_label_configured"] = True
            options = _first(inst, "routing-options")
            if options:
                for key in ("multipath", "auto-export"):
                    if self.flag(_first(options, key), key):
                        entry[key.replace("-", "_") + "_configured"] = True
            protocols = _first(inst, "protocols")
            if protocols:
                names = [name for name in ("bgp", "ospf", "isis", "evpn", "ldp", "rsvp")
                         if _first(protocols, name)]
                if names:
                    entry["configured_protocols"] = names
            evpn = _first(protocols, "evpn")
            if evpn:
                evpn_data = {}
                symmetrical = _first(evpn, "irb-symmetric-routing")
                if symmetrical:
                    vni = self.integer(symmetrical, "vni", low=1, high=16777215)
                    if vni is not None:
                        evpn_data["irb_symmetric_routing_vni"] = vni
                prefix_routes = _first(evpn, "ip-prefix-routes")
                if prefix_routes:
                    options = {}
                    if self.flag(_first(prefix_routes, "advertise"), "advertise direct-nexthop"):
                        options["advertise_direct_nexthop_configured"] = True
                    encap = self.value(prefix_routes, "encapsulation", allowed={"vxlan", "mpls"})
                    if encap:
                        options["encapsulation"] = encap
                    vni = self.integer(prefix_routes, "vni", low=1, high=16777215)
                    if vni is not None:
                        options["vni"] = vni
                    policy = self.value(prefix_routes, "import")
                    if policy:
                        options["import_policy"] = policy
                    if options:
                        evpn_data["ip_prefix_routes"] = options
                if evpn_data:
                    entry["evpn"] = evpn_data
            results.append(entry)
        return results

    def _interfaces(self, root: Any | None) -> list[dict[str, Any]]:
        results = []
        for interface in _ch(root):
            parts = _t(interface)
            if len(parts) != 1:
                continue
            physical: dict[str, Any] = {}
            if self.flag(_first(interface, "vlan-tagging"), "vlan-tagging"):
                physical["vlan_tagging_configured"] = True
            vdsl = _first(interface, "vdsl-options")
            profile = self.value(vdsl, "vdsl-profile", allowed={"auto", "8a", "8b", "8c", "8d", "12a", "12b", "17a"})
            if profile:
                physical["vdsl_profile"] = profile
            if self.flag(_first(interface, "no-per-unit-scheduler"), "no-per-unit-scheduler"):
                physical["no_per_unit_scheduler_configured"] = True
            trace_flag = self.value(_first(interface, "traceoptions"), "flag")
            if trace_flag and trace_flag in {"all", "ppp", "pppoe"}:
                physical["trace_flag_configured"] = trace_flag
            for unit in _ch(interface, "unit"):
                ut = _t(unit)
                if len(ut) != 2:
                    continue
                entry: dict[str, Any] = {"name": parts[0] + "." + ut[1]}
                if physical:
                    entry["physical_settings"] = dict(physical)
                vlan_id = self.integer(unit, "vlan-id", low=1, high=4094)
                if vlan_id is not None:
                    entry["vlan_id"] = vlan_id
                encapsulation = self.value(unit, "encapsulation", allowed={"ppp-over-ether", "ethernet-bridge", "vlan-bridge"})
                if encapsulation:
                    entry["encapsulation"] = encapsulation
                pppoe = _first(unit, "pppoe-options")
                pppoe_data: dict[str, Any] = {}
                underlying = self.value(pppoe, "underlying-interface")
                if underlying and re.fullmatch(r"[A-Za-z][\w./:-]{0,63}", underlying):
                    pppoe_data["underlying_interface"] = underlying
                reconnect = self.integer(pppoe, "auto-reconnect", low=0, high=86400)
                if reconnect is not None:
                    pppoe_data["auto_reconnect_seconds"] = reconnect
                if self.flag(_first(pppoe, "client"), "client"):
                    pppoe_data["client_configured"] = True
                service = _first(pppoe, "service-name")
                if service and len(_t(service)) >= 2:
                    # Le nom du fournisseur peut être une information privée.
                    pppoe_data["service_name_configured"] = True
                    self.take(service)
                if pppoe_data:
                    entry["pppoe"] = pppoe_data
                pap = _first(_first(unit, "ppp-options"), "pap")
                pap_data: dict[str, Any] = {}
                if self.flag(_first(pap, "passive"), "passive"):
                    pap_data["passive_configured"] = True
                for key, output in (("local-name", "login_configured"),
                                    ("local-password", "secret_configured")):
                    node = _first(pap, key)
                    if node and len(_t(node)) >= 2:
                        pap_data[output] = True
                        self.take(node)
                if pap_data:
                    pap_data["credentials_redacted"] = True
                    entry["pap_authentication"] = pap_data
                families = {}
                for fam in _ch(unit, "family"):
                    ft = _t(fam)
                    if len(ft) != 2:
                        continue
                    if ft[1] == "inet6":
                        addresses = []
                        for address in _ch(fam, "address"):
                            at = _t(address)
                            if len(at) == 2:
                                parsed = _prefix(at[1])
                                if parsed and ":" in parsed:
                                    addresses.append(parsed)
                                    self.take(address)
                        families["inet6"] = {"addresses": addresses}
                    if ft[1] == "mpls" and not _ch(fam):
                        self.take(fam)
                        families["mpls"] = {"configured": True}
                    if ft[1] == "inet":
                        gateways = []
                        ipv4_addresses = []
                        for address in _ch(fam, "address"):
                            tokens = _t(address)
                            if len(tokens) == 2:
                                try:
                                    parsed = ipaddress.ip_interface(tokens[1])
                                    if parsed.version == 4:
                                        ipv4_addresses.append(str(parsed))
                                        self.take(address)
                                except ValueError:
                                    pass
                            for gateway in _ch(address, "virtual-gateway-address"):
                                gt = _t(gateway)
                                if len(gt) == 2 and _ip(gt[1]):
                                    gateways.append(_ip(gt[1]))
                                    self.take(gateway)
                        inet: dict[str, Any] = {"virtual_gateways": gateways}
                        if ipv4_addresses:
                            inet["addresses"] = ipv4_addresses
                        if self.flag(_first(fam, "dhcp"), "dhcp"):
                            inet["dhcp_configured"] = True
                        if self.flag(_first(fam, "negotiate-address"), "negotiate-address"):
                            inet["negotiate_address_configured"] = True
                        # ``family inet`` isolé indique une déclaration, pas
                        # une adresse IPv4 ni une interface opérationnelle.
                        if self.flag(fam, "family inet"):
                            inet["family_configured"] = True
                        if len(inet) > 1:
                            families["inet"] = inet
                    if ft[1] == "ethernet-switching":
                        switching = {}
                        mode = self.value(fam, "interface-mode", allowed={"access", "trunk"})
                        if mode:
                            switching["interface_mode"] = mode
                        vlan = _first(fam, "vlan")
                        if vlan:
                            members = _first(vlan, "members")
                            mt = _t(members) if members else []
                            if len(mt) > 1:
                                switching["vlan_members"] = [v for v in mt[1:] if v not in ("[", "]")]
                                self.take(members)
                        if switching:
                            families["ethernet_switching"] = switching
                if families:
                    entry["families"] = families
                if families or physical or any(k in entry for k in
                                            ("vlan_id", "encapsulation", "pppoe", "pap_authentication")):
                    results.append(entry)
        return results

    def _interface_ranges(self, root: Any | None) -> list[dict[str, Any]]:
        ranges = []
        for iface_range in _ch(root, "interface-range"):
            tokens = _t(iface_range)
            if len(tokens) != 2:
                continue
            item: dict[str, Any] = {"name": tokens[1]}
            members = []
            for member in _ch(iface_range, "member"):
                mt = _t(member)
                if len(mt) == 2 and re.fullmatch(r"[A-Za-z][\w*./\[\],-]{1,63}", mt[1]):
                    members.append(mt[1])
                    self.take(member)
            if members:
                item["members"] = members
            assigned_vlans = []
            for unit in _ch(iface_range, "unit"):
                for family in _ch(unit, "family"):
                    if _t(family) == ["family", "ethernet-switching"]:
                        for vlan in _ch(family, "vlan"):
                            for member in _ch(vlan, "members"):
                                values = _t(member)[1:]
                                if values:
                                    assigned_vlans.extend(values)
                                    self.take(member)
            if assigned_vlans:
                item["vlan_members"] = assigned_vlans
            if len(item) > 1:
                ranges.append(item)
        return ranges

    def _auxiliary(self, roots: dict[str, Any]) -> dict[str, Any]:
        data: dict[str, Any] = {}
        system_services = _first(roots.get("system"), "services")
        ssh = _first(system_services, "ssh")
        if self.flag(ssh, "ssh"):
            data["system"] = {"ssh_configured": True}
        security = roots.get("security")
        forwarding = _first(security, "forwarding-options")
        family = _first(forwarding, "family")
        modes = []
        for item in _ch(family):
            parts = _t(item)
            mode = self.value(item, "mode", allowed={"packet-based", "flow-based"})
            if len(parts) == 1 and mode:
                modes.append({"family": parts[0], "configured_mode": mode})
        if modes:
            data["security"] = {"forwarding_family_modes": modes}

        if security:
            # Ne dériver ni la portée effective du pare-feu, ni l'état de session.
            security_data = data.setdefault("security", {})
            zones = []
            zones_node = _first(security, "zones")
            for zone in _ch(zones_node, "security-zone"):
                tokens = _t(zone)
                if len(tokens) != 2:
                    continue
                item: dict[str, Any] = {"name": tokens[1]}
                screen = self.value(zone, "screen")
                if screen:
                    item["screen_profile"] = screen
                inbound = _first(zone, "host-inbound-traffic")
                if inbound:
                    sys_services = [token for leaf in _ch(inbound, "system-services")
                                    for token in _t(leaf)[1:]]
                    protocols = [token for leaf in _ch(inbound, "protocols")
                                 for token in _t(leaf)[1:]]
                    if sys_services:
                        item["inbound_system_services"] = sys_services
                        for leaf in _ch(inbound, "system-services"):
                            self.take(leaf)
                    if protocols:
                        item["inbound_protocols"] = protocols
                        for leaf in _ch(inbound, "protocols"):
                            self.take(leaf)
                assigned = []
                interfaces_node = _first(zone, "interfaces")
                interface_nodes = _ch(interfaces_node)
                if interfaces_node and _t(interfaces_node)[:1] == ["interfaces"] and len(_t(interfaces_node)) == 2:
                    interface_nodes.append(interfaces_node)
                for interface in interface_nodes:
                    name = _t(interface)
                    if not name:
                        continue
                    interface_name = name[1] if name[0] == "interfaces" and len(name) == 2 else name[0]
                    if not re.fullmatch(r"[A-Za-z][\w./:-]{0,63}", interface_name):
                        continue
                    assignment: dict[str, Any] = {"name": interface_name}
                    self.take(interface)
                    local_inbound = _first(interface, "host-inbound-traffic")
                    if local_inbound:
                        for key, output in (("system-services", "inbound_system_services"),
                                            ("protocols", "inbound_protocols")):
                            values = []
                            for leaf in _ch(local_inbound, key):
                                tokens = _t(leaf)
                                if len(tokens) > 1:
                                    values.extend(tokens[1:])
                                    self.take(leaf)
                            if values:
                                assignment[output] = values
                    assigned.append(assignment)
                if assigned:
                    item["interfaces"] = assigned
                zones.append(item)
            if zones:
                security_data["zones"] = zones

            rules = []
            policy_root = _first(security, "policies")
            for from_zone in _ch(policy_root, "from-zone"):
                ft = _t(from_zone)
                if len(ft) != 2:
                    continue
                for to_zone in _ch(from_zone, "to-zone"):
                    tt = _t(to_zone)
                    if len(tt) != 2:
                        continue
                    for policy in _ch(to_zone, "policy"):
                        pt = _t(policy)
                        if len(pt) != 2:
                            continue
                        item = {"name": pt[1], "from_zone": ft[1], "to_zone": tt[1]}
                        matching = _first(policy, "match")
                        for key in ("source-address", "destination-address", "application"):
                            values = [part for leaf in _ch(matching, key)
                                      for part in _t(leaf)[1:]]
                            if values:
                                item[key.replace("-", "_")] = values
                                for leaf in _ch(matching, key):
                                    self.take(leaf)
                        then = _first(policy, "then")
                        for action in ("permit", "deny", "reject"):
                            if self.flag(_first(then, action), action) or self.flag(then, "then " + action):
                                item["configured_action"] = action
                        rules.append(item)
            if rules:
                security_data["policies"] = rules

            source_nat = _first(_first(security, "nat"), "source")
            nat_rules = []
            for rule_set in _ch(source_nat, "rule-set"):
                rt = _t(rule_set)
                if len(rt) != 2:
                    continue
                src = self.value(_first(rule_set, "from"), "zone")
                dst = self.value(_first(rule_set, "to"), "zone")
                for rule in _ch(rule_set, "rule"):
                    tok = _t(rule)
                    if len(tok) != 2:
                        continue
                    item = {"rule_set": rt[1], "name": tok[1]}
                    if src:
                        item["from_zone"] = src
                    if dst:
                        item["to_zone"] = dst
                    match = _first(rule, "match")
                    for key in ("source-address", "destination-address"):
                        addr = self.value(match, key)
                        if addr:
                            try:
                                item[key.replace("-", "_")] = str(ipaddress.ip_network(addr, strict=False))
                            except ValueError:
                                continue
                    then = _first(rule, "then")
                    src_nat = _first(then, "source-nat")
                    if self.flag(_first(src_nat, "interface"), "interface") or self.flag(src_nat, "source-nat interface"):
                        item["translation"] = "interface"
                    if "translation" in item:
                        nat_rules.append(item)
            if nat_rules:
                security_data["source_nat_rules"] = nat_rules

            screens = []
            screen_root = _first(security, "screen")
            for option in _ch(screen_root, "ids-option"):
                ot = _t(option)
                if len(ot) != 2:
                    continue
                item: dict[str, Any] = {"name": ot[1], "checks": [], "syn_flood": {}}
                for family, names in (("icmp", ("ping-death",)),
                                      ("ip", ("source-route-option", "tear-drop")),
                                      ("tcp", ("land",))):
                    parent = _first(option, family)
                    for key in names:
                        if (self.flag(_first(parent, key), key)
                                or any(self.flag(item, family + " " + key)
                                       for item in _ch(option, family))):
                            item["checks"].append(family + "." + key)
                syn = _first(_first(option, "tcp"), "syn-flood")
                for key in ("alarm-threshold", "attack-threshold", "source-threshold",
                            "destination-threshold", "timeout"):
                    number = self.integer(syn, key, low=1, high=1000000)
                    if number is not None:
                        item["syn_flood"][key.replace("-", "_")] = number
                if item["checks"] or item["syn_flood"]:
                    screens.append(item)
            if screens:
                security_data["screens"] = screens

            flow = _first(security, "flow")
            tcp_mss = _first(flow, "tcp-mss")
            all_tcp = _first(tcp_mss, "all-tcp")
            mss = self.integer(all_tcp, "mss", low=64, high=65535)
            if mss is not None:
                security_data["tcp_mss_all_tcp_bytes"] = mss
            if not security_data:
                data.pop("security", None)

        sw = roots.get("switch-options")
        if sw:
            settings = {}
            for key in ("vtep-source-interface", "route-distinguisher", "vrf-target"):
                value = self.value(sw, key)
                if value:
                    settings[key.replace("-", "_")] = value
            if settings:
                data["switch_options"] = settings

        fwd = roots.get("forwarding-options")
        profiles = []
        for storm in _ch(fwd, "storm-control-profiles"):
            tokens = _t(storm)
            if len(tokens) == 2 and self.flag(_first(storm, "all"), "all"):
                profiles.append({"name": tokens[1], "all_configured": True})
        if profiles:
            data["forwarding_options"] = {"storm_control_profiles": profiles}

        ro = roots.get("routing-options")
        routing_data: dict[str, Any] = {}
        table = _first(ro, "forwarding-table")
        if table:
            settings = {}
            export = self.value(table, "export")
            if export:
                settings["export_policy"] = export
            if self.flag(_first(table, "ecmp-fast-reroute"), "ecmp-fast-reroute"):
                settings["ecmp_fast_reroute_configured"] = True
            if settings:
                routing_data["forwarding_table"] = settings
        static_routes = []
        for route in _ch(_first(ro, "static"), "route"):
            tokens = _t(route)
            if len(tokens) != 2:
                continue
            try:
                prefix = str(ipaddress.ip_network(tokens[1], strict=False))
            except ValueError:
                continue
            item: dict[str, Any] = {"prefix": prefix}
            next_hop = self.value(route, "next-hop")
            if next_hop:
                address = _ip(next_hop)
                if address:
                    item["next_hop"] = address
                    item["next_hop_kind"] = "ip"
                elif re.fullmatch(r"[A-Za-z][\w./:-]{1,63}", next_hop):
                    item["next_hop"] = next_hop
                    item["next_hop_kind"] = "interface"
                else:
                    self.accepted.discard(id(_first(route, "next-hop")))
            metric = self.integer(route, "metric", low=0, high=4294967295)
            if metric is not None:
                item["metric"] = metric
            if len(item) > 1:
                static_routes.append(item)
        if static_routes:
            routing_data["static_routes"] = static_routes
        if routing_data:
            data["routing_options"] = routing_data
        return data


def extract_junos_features_v2(
    source_file: str | Path, *, _parsed: Any | None = None,
    _modeled_node_ids: set[int] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Retourne (extension IR v2, compteurs diagnostiques vérifiables)."""
    parser = _parsed if _parsed is not None else load_junos_tree(source_file)
    roots = {(_t(node) or [""])[0]: node for node in parser.config_objs
             if node.parent is node and _t(node) and not is_junos_comment_node(node)}
    v = _Visitor(parser)
    extension = {"protocols": v._protocols(roots.get("protocols")),
                 "routing_instances": v._routing_instances(roots.get("routing-instances")),
                 "interfaces": v._interfaces(roots.get("interfaces")),
                 "auxiliary": v._auxiliary(roots)}
    interface_ranges = v._interface_ranges(roots.get("interfaces"))
    if interface_ranges:
        extension["auxiliary"]["interface_ranges"] = interface_ranges
    counted = Counter()
    accepted = Counter()
    for node in parser.config_objs:
        if node.children or not _t(node) or is_junos_comment_node(node):
            continue
        root = node
        while root.parent is not root:
            root = root.parent
        section = (_t(root) or ["unknown"])[0]
        if section not in {"protocols", "interfaces", "routing-instances", "security",
                           "routing-options", "switch-options", "forwarding-options"}:
            continue
        counted[section] += 1
        if id(node) in v.accepted:
            accepted[section] += 1
    if _modeled_node_ids is not None:
        _modeled_node_ids.update(v.accepted)
    return extension, {"recognized_by_section": dict(accepted),
                       "total_leaves_by_section": dict(counted),
                       "unmodeled_by_section": {k: counted[k] - accepted[k] for k in counted}}
