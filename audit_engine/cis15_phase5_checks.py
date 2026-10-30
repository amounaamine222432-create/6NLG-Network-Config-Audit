"""Contrôles Phase 5 : seuls les éléments explicites de l'IR font foi.

Les contrôles dépendant de l'interface WAN prennent un contexte externe validé.
Les valeurs des secrets ne sont jamais lues, évaluées ou exportées.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Callable


def _read(ir: dict, *path: str) -> Any:
    current: Any = ir
    for part in path:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _missing(complete: bool, detail: dict | None = None) -> tuple[str, dict]:
    data = dict(detail or {})
    if complete:
        data["inferred_absence"] = True
    return ("FAIL" if complete else "UNKNOWN"), data


def _aaa_global(ir: dict, complete: bool, kind: str) -> tuple[str, dict]:
    declarations = _read(ir, "management", "aaa_authentication_" + kind)
    if not isinstance(declarations, list):
        return "UNKNOWN", {"reason": "aaa_not_structured"}
    selected = [m for m in declarations if isinstance(m, dict) and m.get("name") == "default"]
    if not selected:
        return _missing(complete, {"list_name": "default", "configured": False})
    methods = selected[-1].get("methods") or []
    if not methods or "none" in methods:
        return "FAIL", {"list_name": "default", "insecure_none_method": "none" in methods}
    return "PASS", {"list_name": "default", "method_count": len(methods)}


def _line_auth(ir: dict, complete: bool, scope: str) -> tuple[str, dict]:
    lines = _read(ir, "management", "terminal_lines")
    if not isinstance(lines, list):
        return "UNKNOWN", {"scope": scope}
    selected = [l for l in lines if isinstance(l, dict) and
                str(l.get("line_id") or "").lower().startswith(scope)]
    if not selected:
        if scope == "tty " and complete:
            return "NOT_APPLICABLE", {"scope": scope, "line_count": 0}
        return "UNKNOWN", {"scope": scope, "line_count": 0}
    lists = _read(ir, "management", "aaa_authentication_login") or []
    configured = {m.get("name"): m.get("methods") for m in lists if isinstance(m, dict)}
    states = []
    for line in selected:
        method = str(line.get("login_method") or "")
        if method == "disabled" or method == "line_password":
            states.append("FAIL")
        elif method.startswith("authentication "):
            name = method.split(maxsplit=1)[1]
            methods = configured.get(name)
            if _read(ir, "management", "aaa_new_model_enabled") is False:
                states.append("FAIL")
            elif _read(ir, "management", "aaa_new_model_enabled") is None:
                states.append("UNKNOWN")
            elif methods and "none" not in methods:
                states.append("PASS")
            elif methods and "none" in methods:
                states.append("FAIL")
            else:
                states.append("FAIL" if complete else "UNKNOWN")
        else:
            states.append("FAIL" if complete else "UNKNOWN")
    status = "FAIL" if "FAIL" in states else "UNKNOWN" if "UNKNOWN" in states else "PASS"
    evidence = {"scope": scope, "line_count": len(selected),
                "verified_count": states.count("PASS"), "failed_count": states.count("FAIL")}
    if status == "FAIL" and complete and "UNKNOWN" not in states:
        evidence["requires_check_of_referenced_aaa_lists"] = True
    return status, evidence


def _vty_restrictions(ir: dict, complete: bool, *, require_application: bool) -> tuple[str, dict]:
    lines = _read(ir, "management", "terminal_lines") or []
    vty = [l for l in lines if isinstance(l, dict) and
           str(l.get("line_id") or "").lower().startswith("vty ")]
    if not vty:
        return "UNKNOWN", {"vty_line_count": 0}
    acls = _read(ir, "policies", "acls") or []
    named = {str(a.get("name")): a for a in acls if isinstance(a, dict)}
    if not require_application:
        # 1.2.4 vérifie l'existence d'une ACL restrictive, indépendamment
        # de son application (qui relève du contrôle 1.2.5).
        candidates = []
        for acl in named.values():
            entries = acl.get("entries") or []
            permits = [e for e in entries if isinstance(e, dict) and e.get("action") == "permit"]
            if permits and all((e.get("source_match") or {}).get("kind") not in {None, "any"}
                               for e in permits):
                candidates.append(str(acl.get("name")))
        linked = {str(binding.get("acl")) for line in vty
                  for binding in line.get("access_classes") or []
                  if isinstance(binding, dict) and binding.get("direction") == "in"}
        linked_known = linked.intersection(named)
        linked_broad = sorted(linked_known.difference(candidates))
        if linked_broad:
            return "FAIL", {"non_restrictive_vty_acls": linked_broad,
                            "validation_scope": "acl_definition_only"}
        if candidates:
            # Sans liaison VTY, la destination de l'ACL n'est pas prouvée :
            # ne pas promouvoir une ACL restrictive sans rapport en PASS.
            matches = sorted(linked.intersection(candidates))
            return ("PASS" if matches else "UNKNOWN"), {
                "restrictive_acl_count": len(candidates),
                "restrictive_acl_names": candidates,
                "linked_restrictive_acls": matches,
                "validation_scope": "acl_definition_only",
            }
        return _missing(complete, {"restrictive_acl_count": 0,
                                   "validation_scope": "acl_definition_only"})
    missing, broad, valid = 0, 0, 0
    for line in vty:
        incoming = [a.get("acl") for a in line.get("access_classes") or []
                    if isinstance(a, dict) and a.get("direction") == "in"]
        if not incoming:
            missing += 1
            continue
        acl = named.get(str(incoming[-1]))
        if acl is None:
            missing += 1
            continue
        entries = acl.get("entries") or []
        permits = [e for e in entries if isinstance(e, dict) and e.get("action") == "permit"]
        if not permits:
            missing += 1
        elif any((e.get("source_match") or {}).get("kind") == "any" or
                 e.get("source_match") is None for e in permits):
            broad += 1
        else:
            valid += 1
    if broad:
        status = "FAIL"
    elif require_application and missing:
        status = "FAIL" if complete else "UNKNOWN"
    elif missing:
        status = "FAIL" if complete else "UNKNOWN"
    else:
        status = "PASS"
    evidence = {"vty_line_count": len(vty), "restricted_count": valid,
                "unresolved_count": missing, "overly_broad_count": broad,
                "validation_scope": "vty_input_acl"}
    if status == "FAIL" and missing and not broad and complete:
        evidence["inferred_absence"] = True
    return status, evidence


def _ospf_area_md5(ir: dict, complete: bool) -> tuple[str, dict]:
    processes = _read(ir, "routing", "ospf")
    if not isinstance(processes, list):
        return "UNKNOWN", {"reason": "ospf_not_structured"}
    if not processes:
        return ("NOT_APPLICABLE" if complete else "UNKNOWN"), {"ospf_process_count": 0}
    applicable, protected, unverified = 0, 0, 0
    for proc in processes:
        areas = {str(x.get("area")) for x in proc.get("network_selectors") or [] if isinstance(x, dict)}
        protections = {str(x.get("area")) for x in proc.get("area_authentication") or []
                       if isinstance(x, dict) and x.get("mode") == "message-digest"}
        applicable += len(areas)
        protected += len(areas & protections)
        if not areas:
            unverified += 1
    if applicable and protected == applicable and not unverified:
        status = "PASS"
    elif applicable and protected < applicable and complete:
        status = "FAIL"
    else:
        status = "UNKNOWN"
    return status, {"ospf_area_count": applicable, "area_md5_count": protected,
                    "processes_without_network_selectors": unverified,
                    "inferred_absence": status == "FAIL"}


def _ospf_interface_md5(ir: dict, complete: bool) -> tuple[str, dict]:
    if not _read(ir, "routing", "ospf"):
        return ("NOT_APPLICABLE" if complete else "UNKNOWN"), {"ospf_process_count": 0}
    selected, unresolved = _matched_protocol_interfaces(
        ir.get("interfaces") or [], _read(ir, "routing", "ospf") or [], "network_selectors"
    )
    if not selected or unresolved:
        return "UNKNOWN", {"configured_ospf_interface_count": 0,
                           "reason": "ospf_interface_membership_not_fully_inferred"}
    missing_key = sum(not i.get("ospf_md5_key_ids") for i in selected)
    wrong_mode = sum(i.get("ospf_authentication_mode") not in {None, "message-digest"} for i in selected)
    if wrong_mode:
        status = "FAIL"
    elif missing_key:
        status = "FAIL" if complete else "UNKNOWN"
    else:
        status = "PASS"
    return status, {"configured_ospf_interface_count": len(selected),
                    "missing_key_count": missing_key, "wrong_mode_count": wrong_mode,
                    "inferred_absence": status == "FAIL" and bool(missing_key)}


def _matched_protocol_interfaces(interfaces: list, processes: list,
                                 selector_key: str) -> tuple[list[dict], bool]:
    """Matcher uniquement des déclarations network explicites et des IP statiques."""
    patterns: list[ipaddress.IPv4Network] = []
    unknown = False
    for process in processes:
        selectors = process.get(selector_key) or []
        if not selectors:
            unknown = True
        for selector in selectors:
            if selector_key == "network_selectors":
                address, wildcard = selector.get("address"), selector.get("wildcard")
            else:
                if not isinstance(selector, list) or len(selector) != 2:
                    unknown = True
                    continue
                address, wildcard = selector
            try:
                mask = str(ipaddress.IPv4Address(
                    0xFFFFFFFF ^ int(ipaddress.IPv4Address(str(wildcard)))))
                patterns.append(ipaddress.IPv4Network(f"{address}/{mask}", strict=False))
            except (ValueError, TypeError):
                unknown = True
    matched = []
    for interface in interfaces:
        if not isinstance(interface, dict):
            continue
        ips = interface.get("ipv4_addresses") or []
        try:
            if any(ipaddress.IPv4Address(str(addr.get("address"))) in net
                   for addr in ips for net in patterns):
                matched.append(interface)
        except ValueError:
            unknown = True
    return matched, unknown


def _eigrp_interface(ir: dict, complete: bool, kind: str) -> tuple[str, dict]:
    processes = _read(ir, "routing", "eigrp") or []
    if not processes:
        return ("NOT_APPLICABLE" if complete else "UNKNOWN"), {"eigrp_process_count": 0}
    # Les processus classiques sont corrélés par réseaux (aucun voisin inféré).
    classic_processes = [p for p in processes if str(p.get("identifier") or "").isdigit()]
    unknown = False
    settings = []
    for proc in processes:
        if not str(proc.get("identifier") or "").isdigit():
            af = proc.get("af_interfaces") or {}
            # "af-interface default" ne permet pas d'identifier les interfaces actives.
            if "default" in af:
                unknown = True
            settings.extend(cfg for name, cfg in af.items()
                            if name != "default" and isinstance(cfg, dict))
    for process in classic_processes:
        selected, unresolved = _matched_protocol_interfaces(
            ir.get("interfaces") or [], [process], "networks"
        )
        unknown |= unresolved
        for interface in selected:
            settings.append((interface.get("eigrp_authentication") or {}).get(
                str(process.get("identifier")), {}))
    if unknown:
        return "UNKNOWN", {"reason": "eigrp_interface_membership_not_fully_inferred"}
    if not settings:
        return _missing(complete, {"eigrp_process_count": len(processes),
                                   "configured_authentication_interfaces": 0})
    chains = {c.get("name"): c for c in (_read(ir, "routing", "key_chains") or [])}
    invalid = 0
    for cfg in settings:
        if kind == "mode":
            invalid += cfg.get("mode") != "md5"
        else:
            name = cfg.get("key_chain")
            chain = chains.get(name)
            invalid += not bool(chain and chain.get("key_string_count", 0) > 0)
    return ("FAIL" if invalid else "PASS"), {
        "configured_authentication_interfaces": len(settings), "invalid_count": invalid,
        "requires_live_interface_membership_confirmation": True,
    }


_BOGON_SOURCES = {
    "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.2.0/24", "192.168.0.0/16",
    "224.0.0.0/3", "255.255.255.255/32",
}


def _source_network(entry: dict) -> str | None:
    src = entry.get("source_match") or {}
    try:
        if src.get("kind") == "host":
            return str(ipaddress.ip_network(str(src.get("address")) + "/32"))
        if src.get("kind") == "network_wildcard":
            wildcard = int(ipaddress.IPv4Address(src.get("wildcard")))
            netmask = str(ipaddress.IPv4Address(0xFFFFFFFF ^ wildcard))
            return str(ipaddress.ip_network(f"{src.get('address')}/{netmask}", strict=False))
    except ValueError:
        pass
    return None


def _external_acl(ir: dict, complete: bool, context: dict,
                  check_sources: bool) -> tuple[str, dict]:
    requested = context.get("external_interfaces") or []
    if not requested:
        return "UNKNOWN", {"reason": "external_interface_not_designated"}
    interfaces = {str(i.get("name")): i for i in ir.get("interfaces") or [] if isinstance(i, dict)}
    acl_by_name = {str(a.get("name")): a for a in _read(ir, "policies", "acls") or []
                   if isinstance(a, dict)}
    found = []
    missing_bindings = []
    for name in requested:
        interface = interfaces.get(name)
        if interface is None:
            return "UNKNOWN", {"reason": "external_interface_not_found", "interface": name}
        applied = [b.get("name") for b in interface.get("acl_bindings") or []
                   if b.get("direction") == "in"]
        if not applied:
            missing_bindings.append(name)
        else:
            found.append((name, acl_by_name.get(str(applied[-1]))))
    if missing_bindings:
        return _missing(complete, {"external_interfaces": requested,
                                   "missing_inbound_acl_count": len(missing_bindings)})
    if any(acl is None for _, acl in found):
        return ("UNKNOWN" if not complete else "FAIL"), {
            "reason": "inbound_acl_not_defined",
            "undefined_acl_binding_count": sum(acl is None for _, acl in found),
            "inferred_absence": bool(complete),
        }
    if not check_sources:
        return "PASS", {"external_interface_count": len(requested),
                        "inbound_acl_count": len(found),
                        "external_designation": "user_supplied"}
    missing = set()
    early_permits = 0
    required_networks = {network: ipaddress.ip_network(network) for network in _BOGON_SOURCES}
    for _, acl in found:
        denied = set()
        for entry in acl.get("entries") or []:
            if entry.get("action") == "remark":
                continue
            source = _source_network(entry)
            source_net = ipaddress.ip_network(source) if source else None
            if source_net is None and (entry.get("source_match") or {}).get("kind") == "any":
                source_net = ipaddress.ip_network("0.0.0.0/0")
            if entry.get("action") == "permit":
                if ((entry.get("source_match") or {}).get("kind") == "any" and denied != _BOGON_SOURCES):
                    early_permits += 1
                elif source_net and any(source_net.overlaps(net) and label not in denied
                                        for label, net in required_networks.items()):
                    early_permits += 1
            if (entry.get("action") == "deny" and entry.get("protocol") == "ip" and
                    (entry.get("destination_match") or {}).get("kind") == "any" and
                    source_net):
                # Un refus de sur-réseau couvre également les réseaux requis.
                denied.update(label for label, net in required_networks.items()
                              if net.subnet_of(source_net))
        missing |= _BOGON_SOURCES - denied
    if early_permits:
        return "FAIL", {"early_broad_permit_count": early_permits,
                        "required_network_count": len(_BOGON_SOURCES)}
    if missing:
        return _missing(complete, {"missing_deny_network_count": len(missing),
                                   "required_network_count": len(_BOGON_SOURCES),
                                   "note": "coverage_by_single_acl_rule_per_network"})
    return "PASS", {"required_network_count": len(_BOGON_SOURCES),
                    "verified_deny_network_count": len(_BOGON_SOURCES),
                    "external_designation": "user_supplied"}


CHECKS: dict[str, Callable[[dict, bool], tuple[str, dict]]] = {
    "aaa_login_default": lambda ir, c: _aaa_global(ir, c, "login"),
    "aaa_enable_default": lambda ir, c: _aaa_global(ir, c, "enable"),
    "aaa_line_console": lambda ir, c: _line_auth(ir, c, "con "),
    "aaa_line_tty": lambda ir, c: _line_auth(ir, c, "tty "),
    "aaa_line_vty": lambda ir, c: _line_auth(ir, c, "vty "),
    "vty_restricting_acl": lambda ir, c: _vty_restrictions(ir, c, require_application=False),
    "vty_access_class": lambda ir, c: _vty_restrictions(ir, c, require_application=True),
    "ospf_area_md5": _ospf_area_md5,
    "ospf_interface_md5": _ospf_interface_md5,
    "eigrp_interface_keychain": lambda ir, c: _eigrp_interface(ir, c, "keychain"),
    "eigrp_interface_md5": lambda ir, c: _eigrp_interface(ir, c, "mode"),
}

CONTEXT_CHECKS: dict[str, Callable[[dict, bool, dict], tuple[str, dict]]] = {
    "external_inbound_acl": lambda ir, c, context: _external_acl(ir, c, context, False),
    "external_antispoof_acl": lambda ir, c, context: _external_acl(ir, c, context, True),
}
