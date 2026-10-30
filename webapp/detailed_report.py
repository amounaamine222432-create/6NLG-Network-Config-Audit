"""Bilan technique sûr construit exclusivement depuis l'IR normalisée.

On ne recopie JAMAIS une ligne de configuration brute dans ce rapport : les
extraits de commandes sont reconstruits à partir de champs explicitement
modélisés. Le template HTML échappe également toutes les données de l'IR.
"""

from __future__ import annotations

from typing import Any


def _atom(value: Any, default: str = "—") -> str:
    """Une valeur lisible sur une seule ligne, même si la source est hostile."""
    if value is None or value == "":
        return default
    return " ".join(str(value).split())[:180]


def _match(data: dict[str, Any] | None) -> str:
    if not isinstance(data, dict):
        return "[sélecteur absent]"
    kind = data.get("kind")
    if kind == "any":
        return "any"
    if kind == "host":
        return f"host {_atom(data.get('address'))}"
    if kind == "network_wildcard":
        return f"{_atom(data.get('address'))} {_atom(data.get('wildcard'))}"
    if kind == "prefix":
        return _atom(data.get("prefix"))
    return "[sélecteur non reconstitué]"


def _port(data: dict[str, Any] | None) -> str:
    if not isinstance(data, dict):
        return ""
    operator = _atom(data.get("operator"), "")
    ports = " ".join(_atom(p) for p in data.get("ports") or [])
    return " ".join(x for x in (operator, ports) if x)


def _interface_blocks(interfaces: list[dict]) -> list[dict]:
    blocks = []
    for item in interfaces:
        lines = [f"interface {_atom(item.get('name'))}"]
        if item.get("description"):
            lines.append(f" description {_atom(item['description'])}")
        for addr in item.get("ipv4_addresses") or []:
            lines.append(f" adresse IPv4 normalisée : {_atom(addr.get('cidr') or addr.get('address'))}")
        if item.get("ipv4_dhcp"):
            lines.append(" adresse IPv4 par DHCP (déclarée)")
        if item.get("ipv4_explicitly_absent"):
            lines.append(" no ip address")
        if item.get("admin_enabled") is True:
            lines.append(" no shutdown")
        elif item.get("admin_enabled") is False:
            lines.append(" shutdown")
        if item.get("vrf"):
            lines.append(f" vrf forwarding {_atom(item['vrf'])}")
        if item.get("nat_role") in ("inside", "outside"):
            lines.append(f" ip nat {item['nat_role']}")
        for binding in item.get("acl_bindings") or []:
            lines.append(f" ip access-group {_atom(binding.get('name'))} {_atom(binding.get('direction'))}")
        if item.get("vlan_tagging"):
            tag = item["vlan_tagging"]
            lines.append(f" encapsulation dot1Q {_atom(tag.get('vlan_id'))}" + (" native" if tag.get("native") else ""))
        for target in item.get("dhcp_relay_targets") or []:
            lines.append(f" ip helper-address {_atom(target)}")
        blocks.append({"title": _atom(item.get("name")), "lines": lines})
    return blocks


def _ospf_blocks(processes: list[dict]) -> list[dict]:
    blocks = []
    for process in processes:
        lines = [f"router ospf {_atom(process.get('process_id'))}"]
        if process.get("router_id"):
            lines.append(f" router-id {_atom(process['router_id'])}")
        for network in process.get("network_selectors") or []:
            lines.append(f" network {_atom(network.get('address'))} {_atom(network.get('wildcard'))} area {_atom(network.get('area'))}")
        for iface in process.get("passive_interfaces") or []:
            lines.append(f" passive-interface {_atom(iface)}")
        for iface in process.get("non_passive_interfaces") or []:
            lines.append(f" no passive-interface {_atom(iface)}")
        if process.get("redistribution_present"):
            lines.append(" redistribution présente (détails dans l'IR)")
        if process.get("default_information_originate"):
            lines.append(" default-information originate (déclaré)")
        blocks.append({"title": f"Processus OSPF {_atom(process.get('process_id'))}", "lines": lines})
    return blocks


def _bgp_blocks(processes: list[dict]) -> list[dict]:
    blocks = []
    for process in processes:
        lines = [f"router bgp {_atom(process.get('local_as'))}"]
        if process.get("router_id"):
            lines.append(f" bgp router-id {_atom(process['router_id'])}")
        for peer in process.get("neighbors") or []:
            identifier = _atom(peer.get("id"))
            if peer.get("remote_as") is not None:
                lines.append(f" neighbor {identifier} remote-as {_atom(peer['remote_as'])}")
            if peer.get("peer_group"):
                lines.append(f" neighbor {identifier} peer-group {_atom(peer['peer_group'])}")
            for policy in peer.get("policies") or []:
                lines.append(f" neighbor {identifier} route-map {_atom(policy.get('policy_name'))} {_atom(policy.get('direction'))}")
            if peer.get("inherited_policy_references"):
                lines.append(f" neighbor {identifier} : politiques héritées présentes (voir IR)")
        for statement in process.get("network_statements") or []:
            prefix = _atom(statement.get("address"))
            mask = f" mask {_atom(statement['mask'])}" if statement.get("mask") else " (masque non explicite)"
            lines.append(f" network {prefix}{mask}")
        blocks.append({"title": f"AS {_atom(process.get('local_as'))}", "lines": lines})
    return blocks


def _static_blocks(routes: list[dict]) -> list[dict]:
    if not routes:
        return []
    lines = []
    for route in routes:
        vrf = f" vrf {_atom(route['vrf'])}" if route.get("vrf") else ""
        hop = _atom(route.get("next_hop") or route.get("outgoing_interface"))
        lines.append(f"ip route{vrf} {_atom(route.get('destination'))} {_atom(route.get('mask'))} {hop}")
    return [{"title": "Routes statiques", "lines": lines}]


def _acl_blocks(acls: list[dict]) -> list[dict]:
    blocks = []
    for acl in acls:
        lines = [f"ip access-list {_atom(acl.get('type'))} {_atom(acl.get('name'))}"]
        for entry in acl.get("entries") or []:
            parts = [" " + _atom(entry.get("action"))]
            if entry.get("protocol"):
                parts.append(_atom(entry.get("protocol")))
            parts.append(_match(entry.get("source_match")))
            source_port = _port(entry.get("source_port"))
            if source_port:
                parts.append(source_port)
            if entry.get("destination_match") is not None:
                parts.append(_match(entry.get("destination_match")))
            destination_port = _port(entry.get("destination_port"))
            if destination_port:
                parts.append(destination_port)
            lines.append(" ".join(parts))
            if entry.get("unmodeled_token_count"):
                lines.append("  [options supplémentaires non représentées : voir IR/diagnostics]")
        blocks.append({"title": f"ACL {_atom(acl.get('name'))}", "lines": lines})
    return blocks


def _policy_blocks(policies: dict) -> list[dict]:
    blocks = []
    for prefix_list in policies.get("prefix_lists") or []:
        lines = []
        for entry in prefix_list.get("entries") or []:
            seq = f" seq {_atom(entry['sequence'])}" if entry.get("sequence") is not None else ""
            lines.append(f"ip prefix-list {_atom(prefix_list.get('name'))}{seq} {_atom(entry.get('action'))} {_atom(entry.get('prefix'))}")
        blocks.append({"title": f"Prefix-list {_atom(prefix_list.get('name'))}", "lines": lines})
    for policy in policies.get("route_maps") or []:
        lines = []
        for entry in policy.get("entries") or []:
            lines.append(f"route-map {_atom(policy.get('name'))} {_atom(entry.get('action'))} {_atom(entry.get('sequence'))}")
            for operation in entry.get("operations") or []:
                kind = operation.get("operation")
                if kind == "match_prefix_list":
                    lines.append(" match ip address prefix-list " + " ".join(_atom(v) for v in operation.get("references") or []))
                elif kind == "prepend_as_path":
                    lines.append(" set as-path prepend " + " ".join(_atom(v) for v in operation.get("autonomous_systems") or []))
                else:
                    lines.append(f" [opération modélisée : {_atom(kind)} — voir IR]")
            if entry.get("unmodeled_statement_count"):
                lines.append(" [autres instructions non modélisées]")
        blocks.append({"title": f"Route-map {_atom(policy.get('name'))}", "lines": lines})
    return blocks


def _service_blocks(services: dict, management: dict) -> list[dict]:
    blocks = []
    dhcp = services.get("dhcp") or {}
    for pool in dhcp.get("pools") or []:
        lines = [f"ip dhcp pool {_atom(pool.get('name'))}"]
        if pool.get("subnet"):
            lines.append(f" sous-réseau normalisé : {_atom(pool.get('subnet'))}")
        for gateway in pool.get("gateways") or []:
            lines.append(f" default-router {_atom(gateway)}")
        if pool.get("dns_servers"):
            lines.append(" dns-server " + " ".join(_atom(v) for v in pool["dns_servers"]))
        if pool.get("lease"):
            lease = pool["lease"]
            lines.append(" lease infinite" if lease.get("infinite") else f" durée de bail normalisée : {_atom(lease.get('duration_seconds'))} s")
        blocks.append({"title": f"DHCP : {_atom(pool.get('name'))}", "lines": lines})
    nat = services.get("nat") or {}
    if nat.get("rules"):
        lines = []
        for rule in nat["rules"]:
            if rule.get("kind") == "list_interface":
                suffix = " overload" if rule.get("overload") else ""
                lines.append(f"ip nat inside source list {_atom(rule.get('source_acl'))} interface {_atom(rule.get('interface'))}{suffix}")
            else:
                lines.append(f"[règle NAT normalisée : {_atom(rule.get('kind'))} — détails dans l'IR]")
        blocks.append({"title": "Traduction NAT/PAT", "lines": lines})
    syslog = services.get("syslog") or {}
    lines = [f"logging host {_atom(target.get('address'))}" for target in syslog.get("targets") or []]
    if isinstance(syslog.get("buffered"), dict):
        buf = syslog["buffered"]
        lines.append(f"logging buffered : activé={_atom(buf.get('enabled'))}, taille={_atom(buf.get('size_bytes'))}, sévérité={_atom(buf.get('severity'))}")
    if lines:
        blocks.append({"title": "Journalisation Syslog", "lines": lines})
    ntp = services.get("ntp") or {}
    lines = [f"ntp server {_atom(target.get('target'))}" for target in ntp.get("servers") or []]
    lines += [f"ntp peer {_atom(target.get('target'))}" for target in ntp.get("peers") or []]
    if lines:
        blocks.append({"title": "Synchronisation NTP", "lines": lines})
    lines = []
    if management.get("ssh_version"):
        lines.append(f"ip ssh version {_atom(management['ssh_version'])}")
    if management.get("http_enabled") is True:
        lines.append("ip http server")
    elif management.get("http_enabled") is False:
        lines.append("no ip http server")
    for term in management.get("terminal_lines") or []:
        lines.append(f"line {_atom(term.get('line_id'))}")
        if term.get("transport_input"):
            lines.append(" transport input " + " ".join(_atom(v) for v in term["transport_input"]))
    if lines:
        blocks.append({"title": "Administration distante", "lines": lines})
    snmp = services.get("snmp") or {}
    lines = [f"snmp-server community [SECRET MASQUÉ] {_atom(c.get('access')).upper()}" for c in snmp.get("communities") or []]
    lines.extend(f"snmp-server host {_atom(target.get('address'))} [IDENTIFIANTS MASQUÉS]" for target in snmp.get("targets") or [])
    if snmp.get("groups") or snmp.get("users"):
        lines.append("SNMPv3 : groupes/utilisateurs configurés (secrets non exportés)")
    if lines:
        blocks.append({"title": "Supervision SNMP (expurgée)", "lines": lines})
    return blocks


def build_detailed_devices(devices: list[dict], normalized: list[dict], reviews: list[dict]) -> list[dict]:
    """Joindre métriques, constats sûrs et extrait d'IR par équipement."""
    if not (len(devices) == len(normalized) == len(reviews)):
        raise ValueError("Les collections de résultats ne sont pas alignées")
    results = []
    for index, (summary, source, review) in enumerate(zip(devices, normalized, reviews), start=1):
        ir = source["ir"]
        routing = ir.get("routing") or {}
        policies = ir.get("policies") or {}
        services = ir.get("services") or {}
        management = ir.get("management") or {}
        interfaces = ir.get("interfaces") or []

        capabilities = []
        def feature(name: str, present: bool) -> None:
            if present:
                capabilities.append(name)

        feature("Interfaces IP", bool(interfaces))
        feature("OSPF", bool(routing.get("ospf")))
        feature("BGP", bool(routing.get("bgp")))
        feature("Routes statiques", bool(routing.get("static_routes")))
        feature("ACL", bool(policies.get("acls")))
        feature("Politiques BGP", bool(policies.get("route_maps") or policies.get("prefix_lists")))
        feature("VLAN / 802.1Q", any(i.get("vlan_tagging") or (i.get("switchport") or {}).get("mode") for i in interfaces))
        feature("NAT/PAT", bool((services.get("nat") or {}).get("rules")))
        feature("DHCP", bool((services.get("dhcp") or {}).get("pools")))
        feature("SNMP", bool((services.get("snmp") or {}).get("communities") or (services.get("snmp") or {}).get("users")))
        feature("Syslog", bool((services.get("syslog") or {}).get("targets")))
        feature("NTP", bool((services.get("ntp") or {}).get("servers")))
        feature("SSH", management.get("ssh_version") == 2 or any("ssh" in (v.get("transport_input") or []) for v in management.get("terminal_lines") or []))
        feature("HSRP", any(i.get("hsrp_groups") for i in interfaces))
        feature("VRF", bool(ir.get("vrfs")))

        configs = {
            "interfaces": _interface_blocks(interfaces),
            "ospf": _ospf_blocks(routing.get("ospf") or []),
            "bgp": _bgp_blocks(routing.get("bgp") or []),
            "static": _static_blocks(routing.get("static_routes") or []),
            "acls": _acl_blocks(policies.get("acls") or []),
            "policies": _policy_blocks(policies),
            "services": _service_blocks(services, management),
        }
        results.append({
            "id": index,
            "summary": summary,
            "review": review,
            "ir": ir,
            "capabilities": capabilities,
            "configs": configs,
        })
    return results
