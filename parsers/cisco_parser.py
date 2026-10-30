"""Cisco IOS configuration parser (selected IOS 15.x syntax, not a full IOS grammar).

Supports running-configuration files and common CLI configuration scripts.
Every unsupported command remains visible in ``unparsed_lines`` or the
corresponding stanza's ``other_commands``; this is *not* a policy audit.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path


WRAPPER_COMMANDS = {
    "enable", "disable", "configure terminal", "conf t", "end",
    "exit", "write memory", "wr mem", "copy running-config startup-config",
    "copy run start",
}


def _record_unknown(result: dict, number: int, command: str) -> None:
    result["unparsed_lines"].append({"line": number, "command": command})


def _platform_directive(command: str) -> dict | None:
    """Classify *known* IOS platform directives without inferring runtime state.

    Legacy MMI command meanings and ranges are documented in Cisco's
    Configuration Note for the SOHO 76/77 (OL-2479-02). Their availability
    on a different IOS release/hardware remains unverified. Boot markers
    are configuration file delimiters, not CLI commands.
    """
    p = command.split()

    def recognized(feature: str, value: bool | str | int | dict,
                   *, documentation: str = "vendor_documented",
                   unit: str | None = None, meaning: str | None = None,
                   scope: str | None = None) -> dict:
        item = {"feature": feature, "configured_value": value,
                "documentation_status": documentation, "unit": unit,
                "operational_state": None}
        if meaning:
            item["documented_meaning"] = meaning
        if scope:
            item["documentation_scope"] = scope
            item["documentation_reference"] = "Cisco OL-2479-02"
        return item

    legacy_mmi = "vendor_documented_platform_specific"
    legacy_scope = "Cisco SOHO 76/77 MMI DSL (applicability to IOS 15.x unverified)"

    if p == ["boot-start-marker"]:
        return recognized("boot_section_start_marker", True)
    if p == ["boot-end-marker"]:
        return recognized("boot_section_end_marker", True)
    if p[:2] == ["multilink", "bundle-name"] and len(p) == 3 and p[2] in {
        "authenticated", "endpoint", "both"
    }:
        return recognized("multilink_bundle_name_policy", p[2])
    if p[:2] == ["mmi", "polling-interval"] and len(p) == 3 and p[2].isdecimal() and 1 <= int(p[2]) <= 65535:
        return recognized("mmi_polling_interval_configured_value", int(p[2]),
                          documentation=legacy_mmi, unit="seconds", scope=legacy_scope,
                          meaning="Interval between MMI checks for updated image/configuration on the DSL proxy element")
    if p[:2] == ["mmi", "snmp-timeout"] and len(p) == 3 and p[2].isdecimal() and 1 <= int(p[2]) <= 1800:
        return recognized("mmi_snmp_timeout_configured_value", int(p[2]),
                          documentation=legacy_mmi, unit="seconds", scope=legacy_scope,
                          meaning="Allowed interval between consecutive image-download data blocks over MMI")
    if p == ["no", "mmi", "auto-configure"]:
        return recognized("mmi_auto_configure_explicitly_enabled", False,
                          documentation=legacy_mmi, scope=legacy_scope,
                          meaning="MMI proxy-element auto-provisioning disabled; startup configuration used")
    if p == ["no", "mmi", "pvc"]:
        return recognized("mmi_custom_pvc_configured", False,
                          documentation=legacy_mmi, scope=legacy_scope,
                          meaning="Custom MMI ATM PVC assignment cleared; this does not prove no default PVC exists")
    if p == ["no", "scheduler", "allocate"]:
        return recognized("scheduler_allocate_default_requested", True)
    if (p[:2] == ["scheduler", "allocate"] and len(p) == 4
            and all(t.isdecimal() for t in p[2:])
            and 400 <= int(p[2]) <= 60000 and 100 <= int(p[3]) <= 4000):
        return recognized("scheduler_allocate_custom", {
            "interrupt_microseconds": int(p[2]),
            "process_microseconds": int(p[3]),
        }, unit="microseconds")
    if p == ["no", "process", "cpu", "extended", "history"]:
        return recognized("cpu_extended_history_explicitly_enabled", False)
    if p == ["no", "process", "cpu", "autoprofile", "hog"]:
        return recognized("cpu_autoprofile_hog_explicitly_enabled", False)
    if p == ["no", "service-routing", "capabilities-manager"]:
        return recognized("service_routing_capabilities_manager_explicitly_enabled", False)
    if p == ["service-routing", "capabilities-manager"]:
        return recognized("service_routing_capabilities_manager_explicitly_enabled", True)
    return None


def _parse_global_extension(result: dict, command: str, number: int) -> bool:
    """Parse common global directives encountered in the reference corpora.

    Never classify an arbitrary prefix as supported; unknown variants remain
    in unparsed_lines.  Credentials are represented by presence flags only.
    """
    tokens = command.split()
    g = result["global_settings"]
    ntp = result["ntp"]

    # Cisco IOS: clock timezone <zone> <hours-offset> [minutes-offset].
    # Setting the display zone does NOT prove NTP synchronization.
    if tokens == ["no", "clock", "timezone"]:
        g["clock_timezone"] = None
        return True
    if tokens[:2] == ["clock", "timezone"] and len(tokens) in (4, 5):
        try:
            hours = int(tokens[3])
            minutes = int(tokens[4]) if len(tokens) == 5 else 0
        except ValueError:
            return False
        if not (1 <= len(tokens[2]) <= 7 and -23 <= hours <= 23 and 0 <= minutes < 60):
            return False
        g["clock_timezone"] = {
            "name": tokens[2], "hours_offset": hours,
            "minutes_offset": minutes, "source_line": number,
        }
        return True

    if tokens[:2] == ["ip", "domain-name"] and len(tokens) == 3:
        g["ip_domain_name"] = tokens[2]
        return True
    if tokens in (["no", "ip", "domain-name"], ["no", "ip", "domain", "name"]):
        g["ip_domain_name"] = None
        return True
    if tokens[:2] == ["enable", "secret"] and len(tokens) >= 3:
        g["enable_secret_configured"] = True
        return True
    if tokens == ["no", "enable", "secret"]:
        g["enable_secret_configured"] = False
        return True
    if tokens[:2] == ["enable", "password"] and len(tokens) >= 3:
        g["enable_password_configured"] = True
        return True
    if tokens == ["no", "enable", "password"]:
        g["enable_password_configured"] = False
        return True
    if tokens[:4] == ["crypto", "key", "generate", "rsa"]:
        # This is a CLI request; it does NOT prove that any key currently exists.
        if len(tokens) == 4:
            modulus = None
        elif len(tokens) == 6 and tokens[4] == "modulus" and tokens[5].isdecimal():
            modulus = int(tokens[5])
        else:
            return False
        g["rsa_key_generation_requests"].append({"source_line": number, "modulus": modulus})
        return True
    if tokens == ["aaa", "authentication", "login", "privilege-mode"]:
        g["aaa_login_privilege_mode"] = True
        return True
    if tokens == ["no", "aaa", "authentication", "login", "privilege-mode"]:
        g["aaa_login_privilege_mode"] = False
        return True
    if tokens == ["ip", "bgp-community", "new-format"]:
        g["bgp_community_new_format"] = True
        return True
    if tokens == ["no", "ip", "bgp-community", "new-format"]:
        g["bgp_community_new_format"] = False
        return True
    if tokens == ["no", "ip", "icmp", "rate-limit", "unreachable"]:
        g["icmp_unreachable_rate_limit"] = {"enabled": False, "interval_ms": None}
        return True
    if (tokens[:4] == ["ip", "icmp", "rate-limit", "unreachable"]
            and len(tokens) == 5 and tokens[4].isdecimal()):
        g["icmp_unreachable_rate_limit"] = {"enabled": True, "interval_ms": int(tokens[4])}
        return True
    if tokens[:3] == ["ip", "tcp", "synwait-time"] and len(tokens) == 4 and tokens[3].isdecimal():
        g["tcp_synwait_seconds"] = int(tokens[3])
        return True
    if tokens == ["no", "ip", "tcp", "synwait-time"]:
        g["tcp_synwait_seconds"] = None
        return True
    if tokens in (["ip", "source-route"], ["no", "ip", "source-route"]):
        g["ip_source_route_enabled"] = tokens[0] == "ip"
        return True

    if tokens[:2] == ["ntp", "server"] or tokens[:2] == ["ntp", "peer"]:
        kind = tokens[1]
        idx = 2
        vrf = None
        if len(tokens) > idx + 1 and tokens[idx] == "vrf":
            vrf = tokens[idx + 1]
            idx += 2
        if len(tokens) <= idx:
            return False
        target = tokens[idx]
        idx += 1
        source_interface = None
        key_id = None
        version = None
        prefer = False
        remaining = 0
        while idx < len(tokens):
            option = tokens[idx]
            if option in {"source", "key", "version"} and idx + 1 < len(tokens):
                if option == "source":
                    source_interface = tokens[idx + 1]
                elif option == "key":
                    key_id = tokens[idx + 1]
                else:
                    version = tokens[idx + 1]
                idx += 2
            elif option == "prefer":
                prefer = True
                idx += 1
            else:
                # An unknown option is NOT silently accepted as understood.
                remaining += 1
                idx += 1
        ntp["servers" if kind == "server" else "peers"].append({
            "target": target, "vrf": vrf, "source_interface": source_interface,
            "key_id": key_id, "version": version, "prefer": prefer,
            "unmodeled_token_count": remaining, "source_line": number,
        })
        return True
    if tokens[:2] == ["ntp", "source"] and len(tokens) == 3:
        ntp["source_interface"] = tokens[2]
        return True
    if tokens in (["ntp", "authenticate"], ["no", "ntp", "authenticate"]):
        ntp["authentication_enabled"] = tokens[0] == "ntp"
        return True
    if tokens[:2] == ["ntp", "trusted-key"] and len(tokens) >= 3 and all(t.isdecimal() for t in tokens[2:]):
        ntp["trusted_key_ids"].extend(tokens[2:])
        return True
    if tokens[:2] == ["ntp", "authentication-key"] and len(tokens) >= 5:
        ntp["authentication_keys"].append({
            "key_id": tokens[2], "algorithm": tokens[3],
            "secret_configured": True, "source_line": number,
        })
        return True
    if tokens[:2] == ["ntp", "master"] and (len(tokens) == 2 or (len(tokens) == 3 and tokens[2].isdecimal())):
        ntp["master_stratum"] = int(tokens[2]) if len(tokens) == 3 else None
        ntp["master_configured"] = True
        return True
    if (tokens[:2] == ["ntp", "access-group"] and len(tokens) == 4
            and tokens[2] in {"peer", "serve", "serve-only", "query-only"}):
        ntp["access_groups"].append({"mode": tokens[2], "acl": tokens[3], "source_line": number})
        return True
    if tokens in (["ntp", "update-calendar"], ["no", "ntp", "update-calendar"]):
        ntp["update_calendar_enabled"] = tokens[0] == "ntp"
        return True
    if tokens in (["ntp", "logging"], ["no", "ntp", "logging"]):
        ntp["logging_enabled"] = tokens[0] == "ntp"
        return True
    if tokens[:2] == ["ntp", "clock-period"] and len(tokens) == 3 and tokens[2].isdecimal():
        ntp["clock_period"] = int(tokens[2])
        return True
    return False


def _get_named(collection: list, name: str, **defaults) -> dict:
    for item in collection:
        if item["name"] == name:
            return item
    obj = {"name": name, **defaults}
    collection.append(obj)
    return obj


def _static_route(command: str, number: int) -> dict | None:
    tokens = command.split()
    offset = 2
    vrf = None
    if len(tokens) > offset and tokens[offset] == "vrf":
        if len(tokens) <= offset + 1:
            return None
        vrf = tokens[offset + 1]
        offset += 2
    if len(tokens) < offset + 3:
        return None

    destination, mask = tokens[offset: offset + 2]
    try:
        ipaddress.IPv4Network((destination, mask), strict=False)
    except (ValueError, ipaddress.AddressValueError):
        return None

    path = tokens[offset + 2:]
    if not path:
        return None
    first = path.pop(0)
    next_hop = None
    outgoing_interface = None
    try:
        ipaddress.IPv4Address(first)
        next_hop = first
    except ipaddress.AddressValueError:
        outgoing_interface = first
        if path:
            try:
                ipaddress.IPv4Address(path[0])
                next_hop = path.pop(0)
            except ipaddress.AddressValueError:
                pass

    distance = int(path[0]) if path and path[0].isdecimal() else None
    return {
        "destination": destination, "mask": mask, "vrf": vrf,
        "next_hop": next_hop, "outgoing_interface": outgoing_interface,
        "administrative_distance_configured": distance,
        "options": path, "source_line": number, "raw": command,
    }


def _prefix_list(command: str, number: int) -> tuple[str, dict] | None:
    tokens = command.split()
    if len(tokens) < 5:
        return None
    name = tokens[2]
    index = 3
    sequence = None
    if tokens[index] == "seq":
        if len(tokens) <= index + 2:
            return None
        sequence = tokens[index + 1]
        index += 2
    if len(tokens) <= index + 1 or tokens[index] not in ("permit", "deny"):
        return None
    action, prefix = tokens[index:index + 2]
    try:
        ipaddress.IPv4Network(prefix, strict=False)
    except ValueError:
        return None
    options = tokens[index + 2:]
    ge, le = None, None
    for pos in range(len(options) - 1):
        if options[pos] == "ge":
            ge = options[pos + 1]
        elif options[pos] == "le":
            le = options[pos + 1]
    return name, {
        "sequence": sequence, "action": action, "prefix": prefix,
        "ge": ge, "le": le, "options": options,
        "source_line": number, "raw": command,
    }


def _acl_entry(command: str, number: int) -> dict:
    tokens = command.split()
    seq = None
    if tokens and tokens[0].isdecimal():
        seq = tokens.pop(0)
    action = tokens[0] if tokens and tokens[0] in ("permit", "deny", "remark") else None
    body = " ".join(tokens[1:]) if action else " ".join(tokens)
    result = {"sequence": seq, "action": action, "body": body,
              "protocol": None, "source": None, "destination": None,
              "source_port": None, "destination_port": None,
              "remaining_tokens": [], "source_line": number, "raw": command}
    if action not in ("permit", "deny"):
        return result

    remaining = tokens[1:]
    if remaining and remaining[0] in {
        "ip", "tcp", "udp", "icmp", "gre", "ospf", "eigrp", "esp", "ahp"
    }:
        result["protocol"] = remaining.pop(0)
    result["source"] = _acl_address(remaining)
    if result["protocol"]:
        result["source_port"] = _acl_port(remaining)
        result["destination"] = _acl_address(remaining)
        result["destination_port"] = _acl_port(remaining)
    # IOS ACL log/log-input is a meaningful action modifier; retain it
    # separately from still-unmodeled optional tokens.
    result["logging_mode"] = None
    if remaining and remaining[-1].lower() in ("log", "log-input"):
        result["logging_mode"] = remaining.pop().lower()
    result["remaining_tokens"] = remaining
    return result


def _acl_address(tokens: list[str]) -> dict | None:
    if not tokens:
        return None
    first = tokens.pop(0)
    if first == "any":
        return {"kind": "any"}
    if first == "host" and tokens:
        return {"kind": "host", "address": tokens.pop(0)}
    if first == "object-group" and tokens:
        return {"kind": "object_group", "name": tokens.pop(0)}
    try:
        ipaddress.IPv4Address(first)
        if tokens:
            try:
                ipaddress.IPv4Address(tokens[0])
                return {"kind": "network_wildcard", "address": first,
                        "wildcard": tokens.pop(0)}
            except ValueError:
                pass
        return {"kind": "host_or_unspecified_mask", "address": first}
    except ValueError:
        # Never guess the meaning of an unrecognized ACL address operator.
        tokens.insert(0, first)
        return None


def _acl_port(tokens: list[str]) -> dict | None:
    if not tokens or tokens[0] not in {"eq", "neq", "gt", "lt", "range"}:
        return None
    operator = tokens.pop(0)
    count = 2 if operator == "range" else 1
    if len(tokens) < count:
        tokens.insert(0, operator)
        return None
    return {"operator": operator, "ports": [tokens.pop(0) for _ in range(count)]}


def _hsrp_group(interface: dict, group_id: str) -> dict:
    for group in interface["hsrp_groups"]:
        if group["group_id"] == group_id:
            return group
    group = {"group_id": group_id, "virtual_ip": None, "priority": None,
             "preempt": False, "authentication_configured": False,
             "track_commands": [], "other_commands": []}
    interface["hsrp_groups"].append(group)
    return group


def _interface_extension(interface: dict, command: str) -> bool:
    parts = command.split()
    sw = interface["switchport"]
    if parts[:1] == ["description"]:
        interface["description"] = command[len("description "):]
    elif parts[:1] == ["mtu"] and len(parts) == 2 and parts[1].isdecimal():
        interface["mtu"] = int(parts[1])
    elif parts[:2] == ["ip", "access-group"] and len(parts) == 4 and parts[3] in {"in", "out"}:
        interface["acl_bindings"].append({"name": parts[2], "direction": parts[3]})
    elif parts[:3] == ["ip", "ospf", "network"] and len(parts) == 4:
        if parts[3] not in {"point-to-point", "broadcast", "non-broadcast", "point-to-multipoint"}:
            return False
        interface["ospf_network_type"] = parts[3]
    elif parts[:3] == ["ip", "ospf", "message-digest-key"] and len(parts) >= 6 and parts[4] == "md5":
        # Never retain the password or the original command.
        interface.setdefault("ospf_md5_keys", []).append({"key_id": parts[3], "configured": True})
    elif parts[:3] == ["ip", "ospf", "authentication"] and len(parts) == 4:
        interface["ospf_authentication_mode"] = parts[3]
    elif parts[:3] == ["ip", "authentication", "key-chain"] and len(parts) == 6 and parts[3] == "eigrp":
        interface.setdefault("eigrp_authentication", {}).setdefault(parts[4], {})["key_chain"] = parts[5]
    elif parts[:3] == ["ip", "authentication", "mode"] and len(parts) == 5 and parts[3] == "eigrp":
        # Invalid/incomplete form: do not infer an authentication mode.
        return False
    elif parts[:3] == ["ip", "authentication", "mode"] and len(parts) == 6 and parts[3] == "eigrp":
        interface.setdefault("eigrp_authentication", {}).setdefault(parts[4], {})["mode"] = parts[5].lower()
    elif parts[:1] == ["duplex"] and len(parts) >= 2:
        interface["duplex"] = parts[1]
    elif parts[:1] == ["speed"] and len(parts) >= 2:
        interface["speed"] = parts[1]
    elif parts[:2] == ["media-type", "rj45"]:
        interface["media_type"] = parts[1]
    elif parts[:1] == ["media-type"] and len(parts) >= 2:
        interface["media_type"] = parts[1]
    elif parts[:2] == ["negotiation", "auto"]:
        interface["negotiation"] = "auto"
    elif parts[:2] == ["no", "cdp"] and len(parts) >= 3 and parts[2] == "enable":
        interface["cdp_enabled"] = False
    elif parts[:2] == ["cdp", "enable"]:
        interface["cdp_enabled"] = True
    elif parts[:2] == ["vrf", "forwarding"] and len(parts) >= 3:
        interface["vrf_forwarding"] = parts[2]
    elif parts[:3] == ["ip", "vrf", "forwarding"] and len(parts) >= 4:
        interface["vrf_forwarding"] = parts[3]
    elif parts[:2] == ["ip", "helper-address"] and len(parts) >= 3:
        interface["ip_helper_addresses"].append(parts[-1])
    elif parts[:2] == ["ip", "nat"] and len(parts) == 3 and parts[2] in {"inside", "outside"}:
        interface["nat_role"] = parts[2]
    elif parts == ["no", "ip", "proxy-arp"]:
        interface["proxy_arp_enabled"] = False
    elif parts == ["ip", "proxy-arp"]:
        interface["proxy_arp_enabled"] = True
    elif parts[:2] == ["switchport", "mode"] and len(parts) >= 3:
        sw["mode"] = parts[2]
    elif parts[:3] == ["switchport", "access", "vlan"] and len(parts) >= 4:
        sw["access_vlan"] = parts[3]
    elif (parts[:3] == ["switchport", "trunk", "encapsulation"]
          and len(parts) == 4 and parts[3] in {"dot1q", "isl", "negotiate"}):
        sw["trunk_encapsulation"] = parts[3]
    elif parts == ["no", "switchport", "trunk", "encapsulation"]:
        sw["trunk_encapsulation"] = None
    elif parts[:4] == ["switchport", "trunk", "native", "vlan"] and len(parts) >= 5:
        sw["native_vlan"] = parts[4]
    elif parts[:4] == ["switchport", "trunk", "allowed", "vlan"] and len(parts) >= 5:
        sw["allowed_vlan_commands"].append(" ".join(parts[4:]))
    elif parts[:2] == ["encapsulation", "dot1Q"] and len(parts) >= 3:
        interface["dot1q"] = {"vlan_id": parts[2], "native": "native" in parts[3:]}
    elif parts[:2] == ["standby", "version"] and len(parts) >= 3:
        interface["hsrp_version"] = parts[2]
    elif parts and parts[0] == "standby" and len(parts) >= 3:
        group = _hsrp_group(interface, parts[1])
        if parts[2] == "ip" and len(parts) >= 4:
            group["virtual_ip"] = parts[3]
        elif parts[2] == "priority" and len(parts) >= 4:
            group["priority"] = parts[3]
        elif parts[2] == "preempt":
            group["preempt"] = True
            if len(parts) > 3:
                group["other_commands"].append(command)
        elif parts[2] == "authentication":
            group["authentication_configured"] = True
            # Do not export authentication material in this field.
        elif parts[2] == "track":
            group["track_commands"].append(command)
        else:
            group["other_commands"].append(command)
    else:
        return False
    return True


def _parse_line_command(line: dict, cmd: str) -> bool:
    """Parse terminal-line controls without storing credential values."""
    p = cmd.split()
    if p[:1] == ["exec-timeout"] and len(p) >= 2:
        line["exec_timeout"] = p[1:]
    elif p[:2] == ["privilege", "level"] and len(p) == 3 and p[2].isdecimal():
        line["privilege_level"] = int(p[2])
    elif p[:1] == ["stopbits"] and len(p) == 2 and p[1].isdecimal():
        line["stopbits"] = int(p[1])
    elif p[:1] == ["login"]:
        line["login_method"] = " ".join(p[1:]) or "line_password"
    elif p[:1] == ["access-class"] and len(p) >= 3 and p[2] in {"in", "out"}:
        line.setdefault("access_classes", []).append({"acl": p[1], "direction": p[2],
                                                      "vrf_also": "vrf-also" in p[3:]})
    elif p[:2] == ["no", "login"]:
        line["login_method"] = "disabled"
    elif p[:2] == ["transport", "input"]:
        line["transport_input"] = p[2:]
    elif p[:2] == ["transport", "output"]:
        line["transport_output"] = p[2:]
    elif p[:2] == ["logging", "synchronous"]:
        line["logging_synchronous"] = True
    elif p[:1] == ["password"]:
        line["password_configured"] = True
    else:
        return False
    return True


def _account(cmd: str, number: int) -> dict | None:
    """Represent configured accounts without exporting hashes or passwords."""
    p = cmd.split()
    if len(p) < 2 or p[0] != "username":
        return None
    privilege = p[p.index("privilege") + 1] if "privilege" in p and p.index("privilege") + 1 < len(p) else None
    credential_kind = "secret" if "secret" in p else "password" if "password" in p else None
    return {"name": p[1], "privilege": privilege,
            "credential_kind": credential_kind,
            "credential_configured": credential_kind is not None,
            "source_line": number}


def _nat_global(result: dict, cmd: str, number: int) -> bool:
    p = cmd.split()
    if p[:3] == ["ip", "nat", "pool"] and len(p) >= 7:
        result["nat_pools"].append({
            "name": p[3], "start_address": p[4], "end_address": p[5],
            "addressing_option": " ".join(p[6:]), "source_line": number,
            "raw": cmd,
        })
    elif p[:4] == ["ip", "nat", "inside", "source"]:
        rule = {"source_line": number, "kind": "other", "acl": None,
                "pool": None, "interface": None, "inside_local": None,
                "inside_global": None, "overload": "overload" in p,
                "protocol": None, "inside_port": None, "outside_port": None,
                "raw": cmd, "options": p[4:]}
        t = p[4:]
        if len(t) >= 6 and t[:2] in (["static", "tcp"], ["static", "udp"]):
            rule.update(kind="static_port", protocol=t[1],
                        inside_local=t[2], inside_port=t[3],
                        inside_global=t[4], outside_port=t[5])
        elif len(t) >= 3 and t[0] == "static":
            rule.update(kind="static", inside_local=t[1], inside_global=t[2])
        elif len(t) >= 4 and t[0] == "list":
            rule["acl"] = t[1]
            if t[2] == "pool":
                rule.update(kind="list_pool", pool=t[3])
            elif t[2] == "interface":
                rule.update(kind="list_interface", interface=t[3])
        result["nat_rules"].append(rule)
    elif p[:2] == ["ip", "nat"]:
        result["nat_other_commands"].append(cmd)
    else:
        return False
    return True


_LOG_SEVERITIES = {
    "emergencies": 0, "alerts": 1, "critical": 2, "errors": 3,
    "warnings": 4, "notifications": 5, "informational": 6, "debugging": 7,
}


def _buffered_logging(tokens: list[str], number: int) -> dict | None:
    """Parse the bounded IOS syntax; unknown options remain unmodeled."""
    if tokens == ["no", "logging", "buffered"]:
        return {"enabled": False, "size_bytes": None, "severity": None,
                "discriminator_configured": False, "source_line": number}
    if tokens == ["default", "logging", "buffered"]:
        return {"enabled": None, "size_bytes": None, "severity": None,
                "discriminator_configured": False, "default_requested": True,
                "source_line": number}
    if tokens[:2] != ["logging", "buffered"]:
        return None
    opts = tokens[2:]
    index = 0
    discriminator = False
    if len(opts) >= 2 and opts[0] == "discriminator":
        if not (1 <= len(opts[1]) <= 8 and opts[1].isalnum()):
            return None
        discriminator = True
        index = 2
    size = None
    severity = None
    if index < len(opts) and opts[index].isdecimal() and int(opts[index]) >= 4096:
        size = int(opts[index])
        if size > 2147483647:
            return None
        index += 1
    if index < len(opts):
        label = opts[index].lower()
        if label in _LOG_SEVERITIES:
            severity = _LOG_SEVERITIES[label]
        elif label.isdecimal() and 0 <= int(label) <= 7:
            severity = int(label)
        else:
            return None
        index += 1
    if index != len(opts):
        return None
    return {"enabled": True, "size_bytes": size, "severity": severity,
            "discriminator_configured": discriminator, "source_line": number}


def _snmp_group(tokens: list[str], number: int) -> dict | None:
    """Represent v1/v2c/v3 group permissions without copying view names."""
    if len(tokens) < 4 or tokens[:2] != ["snmp-server", "group"]:
        return None
    version = tokens[3]
    if version not in {"v1", "v2c", "v3"}:
        return None
    index = 4
    level = None
    if version == "v3" and index < len(tokens) and tokens[index] in {"auth", "noauth", "priv"}:
        level = tokens[index]
        index += 1
    permissions = set()
    while index < len(tokens):
        option = tokens[index]
        if option not in {"read", "write", "notify", "access", "context"} or index + 1 >= len(tokens):
            return None
        permissions.add(option)
        index += 2
    return {"version": version, "security_level": level,
            "read_configured": "read" in permissions,
            "write_configured": "write" in permissions,
            "notify_configured": "notify" in permissions,
            "access_restricted": "access" in permissions,
            "source_line": number}


def _snmp_user(tokens: list[str], number: int) -> dict | None:
    """Inspect SNMPv3 structure while discarding authentication material."""
    if len(tokens) < 5 or tokens[:2] != ["snmp-server", "user"]:
        return None
    index = 4  # username and group are intentionally not exported.
    remote = False
    if tokens[index] == "remote":
        if index + 1 >= len(tokens):
            return None
        remote = True
        index += 2
        if tokens[index:index + 1] == ["udp-port"]:
            if index + 1 >= len(tokens) or not tokens[index + 1].isdecimal():
                return None
            index += 2
    if index >= len(tokens) or tokens[index] not in {"v1", "v2c", "v3"}:
        return None
    version = tokens[index]
    index += 1
    encrypted = False
    if tokens[index:index + 1] == ["encrypted"]:
        encrypted = True
        index += 1
    authenticated = False
    private = False
    auth_algorithm = None
    privacy_algorithm = None
    access_restricted = False
    while index < len(tokens):
        token = tokens[index]
        if token == "access" and index + 1 < len(tokens):
            access_restricted = True
            index += 2
        elif token == "auth" and version == "v3" and not authenticated:
            if index + 2 >= len(tokens) or tokens[index + 1].lower() not in {
                "md5", "sha", "sha-1", "sha-224", "sha-256", "sha-384", "sha-512"
            }:
                return None
            authenticated = True
            auth_algorithm = tokens[index + 1].lower()
            index += 2
            # Optional IOS password encoding type; never persist the value.
            if tokens[index:index + 1] in (["0"], ["7"]):
                index += 1
            if index >= len(tokens):
                return None
            index += 1
        elif token == "priv" and version == "v3" and not private:
            if index + 2 >= len(tokens) or tokens[index + 1].lower() not in {
                "des", "3des", "aes", "aes-128", "aes-192", "aes-256"
            }:
                return None
            private = True
            privacy_algorithm = tokens[index + 1].lower()
            index += 2
            if privacy_algorithm == "aes" and tokens[index:index + 1] in (["128"], ["192"], ["256"]):
                privacy_algorithm += "-" + tokens[index]
                index += 1
            if tokens[index:index + 1] in (["0"], ["7"]):
                index += 1
            if index >= len(tokens):
                return None
            index += 1
        else:
            return None
    return {"version": version, "remote": remote, "encrypted_marker": encrypted,
            "authentication_configured": authenticated,
            "authentication_algorithm": auth_algorithm,
            "privacy_configured": private,
            "privacy_algorithm": privacy_algorithm,
            "access_restricted": access_restricted, "source_line": number}


def _snmp_syslog_global(result: dict, cmd: str, number: int) -> bool:
    p = cmd.split()
    if p[:2] == ["snmp-server", "community"] and len(p) >= 3:
        result["snmp"]["communities"].append({
            # Le nom de communauté est un secret : ne pas l'exporter en JSON.
            "value": None, "secret_redacted": True,
            "access": next((v for v in p[3:] if v.upper() in ("RO", "RW")), None),
            "options": p[3:], "source_line": number,
        })
    elif p[:2] == ["snmp-server", "host"] and len(p) >= 3:
        opts = p[3:]
        version = opts[opts.index("version") + 1] if "version" in opts and opts.index("version") + 1 < len(opts) else None
        result["snmp"]["hosts"].append({
            "host": p[2], "version": version, "options": opts,
            "source_line": number,
        })
    elif p[:2] in (["snmp-server", "location"], ["snmp-server", "contact"]) and len(p) >= 3:
        # Contact may be an email address, location may be sensitive. Preserve
        # their presence but do not store their free-form values in the IR.
        result["snmp"][p[1] + "_configured"] = True
    elif p[:2] == ["snmp-server", "group"]:
        group = _snmp_group(p, number)
        if group is None:
            result["snmp"]["other_commands"].append(cmd)
        else:
            result["snmp"]["groups"].append(group)
    elif p[:2] == ["snmp-server", "user"]:
        user = _snmp_user(p, number)
        if user is None:
            result["snmp"]["other_commands"].append(cmd)
        else:
            result["snmp"]["users"].append(user)
    elif p[:3] == ["snmp-server", "enable", "traps"]:
        # The notification family is useful for audit; variant-specific
        # options are counted, not assumed to be semantically understood.
        result["snmp"]["traps_enabled"] = True
        result["snmp"]["trap_rules"].append({
            "family": p[3] if len(p) >= 4 else "all",
            "option_count": max(0, len(p) - 4), "source_line": number,
        })
    elif p in (["no", "snmp-server", "location"], ["no", "snmp-server", "contact"]):
        result["snmp"][p[2] + "_configured"] = False
    elif p == ["no", "snmp-server", "enable", "traps"]:
        result["snmp"]["traps_enabled"] = False
    elif p and p[0] == "snmp-server":
        result["snmp"]["other_commands"].append(cmd)
    elif p[:2] == ["logging", "buffered"] or p in (
        ["no", "logging", "buffered"], ["default", "logging", "buffered"]
    ):
        settings = _buffered_logging(p, number)
        if settings is None:
            result["syslog"]["other_commands"].append(cmd)
        else:
            result["syslog"]["buffered"] = settings
    elif p[:2] == ["logging", "host"] and len(p) >= 3:
        result["syslog"]["hosts"].append({"host": p[2], "options": p[3:], "source_line": number})
    elif p[:2] == ["logging", "source-interface"] and len(p) >= 3:
        result["syslog"]["source_interface"] = p[2]
    elif p[:2] == ["logging", "trap"] and len(p) >= 3:
        result["syslog"]["trap_level"] = p[2]
    elif p and p[0] == "logging" and len(p) >= 2:
        # Legacy IOS commonly uses `logging 192.0.2.10` instead of `logging host`.
        try:
            ipaddress.ip_address(p[1])
            result["syslog"]["hosts"].append({"host": p[1], "options": p[2:], "source_line": number})
        except ValueError:
            result["syslog"]["other_commands"].append(cmd)
    else:
        return False
    return True


def _complete_bgp(result: dict) -> None:
    for bgp in result["bgp_processes"]:
        by_id = {n["id"]: n for n in bgp["neighbors"]}
        for n in bgp["neighbors"]:
            group = by_id.get(n["peer_group"]) if n["peer_group"] else None
            inherited_as = group["remote_as"] if group else None
            effective_as = n["remote_as"] or inherited_as
            n["effective_remote_as"] = effective_as
            n["remote_as_inherited_from"] = (group["id"] if group and not n["remote_as"] else None)
            n["session_type_configured"] = (
                "ibgp" if effective_as == bgp["local_as"] else "ebgp"
            ) if effective_as else None


def _neighbor(bgp: dict, identifier: str, number: int) -> dict:
    for neighbor in bgp["neighbors"]:
        if neighbor["id"] == identifier:
            return neighbor
    neighbor = {
        "id": identifier, "source_line": number, "is_peer_group": False,
        "peer_group": None, "remote_as": None, "update_source": None,
        "description_configured": False, "description_source_line": None,
        "password_configured": False, "password_source_line": None,
        "activated_families": [], "route_maps": [],
        "send_community_by_family": {}, "advertise_additional_paths": [],
        "route_reflector_client_families": [],
        "global_commands": [], "address_family_commands": {},
    }
    bgp["neighbors"].append(neighbor)
    return neighbor


def _parse_bgp_line(bgp: dict, command: str, number: int, family: str | None) -> None:
    tokens = command.split()
    af = next((a for a in bgp["address_families"] if a["name"] == family), None) if family else None
    if tokens == ["bgp", "log-neighbor-changes"] and not family:
        bgp["log_neighbor_changes"] = True
    elif af is not None and tokens == ["bgp", "dampening"]:
        af["dampening_configured"] = True
    elif af is not None and tokens[:2] == ["bgp", "additional-paths"] and tokens[2:] in (
        ["select", "all"], ["send", "receive"], ["send"], ["receive"]
    ):
        af["additional_paths_commands"].append({"operation": tokens[2], "options": tokens[3:]})
    elif (af is not None and tokens[:2] == ["maximum-paths", "eibgp"]
          and len(tokens) == 3 and tokens[2].isdecimal()):
        af["maximum_paths_eibgp"] = int(tokens[2])
    elif (af is not None and tokens[:1] == ["aggregate-address"]
          and len(tokens) in (3, 4) and (len(tokens) == 3 or tokens[3] == "summary-only")):
        try:
            ipaddress.IPv4Network(f"{tokens[1]}/{tokens[2]}", strict=False)
        except ValueError:
            af["other_commands"].append(command)
        else:
            af["aggregate_addresses"].append({
                "address": tokens[1], "mask": tokens[2],
                "summary_only": len(tokens) == 4, "source_line": number,
            })
    elif tokens[:2] == ["bgp", "router-id"] and len(tokens) >= 3:
        bgp["router_id"] = tokens[2]
    elif tokens and tokens[0] == "neighbor" and len(tokens) >= 3:
        n = _neighbor(bgp, tokens[1], number)
        directive = tokens[2:]
        if family:
            # Ne jamais stocker une valeur credential, même sous un AF inattendu.
            if directive[:1] == ["password"]:
                n["password_in_af_unverified"] = True
            else:
                n["address_family_commands"].setdefault(family, []).append(" ".join(directive))
        else:
            if directive[:1] == ["password"] and len(directive) >= 2:
                n["password_configured"] = True
                n["password_source_line"] = number
            else:
                n["global_commands"].append(" ".join(directive))
        if directive == ["peer-group"]:
            n["is_peer_group"] = True
        elif len(directive) >= 2 and directive[0] == "peer-group":
            n["peer_group"] = directive[1]
        elif len(directive) >= 2 and directive[0] == "remote-as":
            n["remote_as"] = directive[1]
        elif len(directive) >= 2 and directive[0] == "update-source":
            n["update_source"] = directive[1]
        elif len(directive) >= 2 and directive[0] == "description":
            # Do not export free-form descriptions: they may contain secrets.
            n["description_configured"] = True
            n["description_source_line"] = number
        elif directive == ["activate"] and family:
            if family not in n["activated_families"]:
                n["activated_families"].append(family)
        elif (len(directive) == 3 and directive[0] == "route-map"
              and directive[2] in {"in", "out"}):
            n["route_maps"].append({
                "name": directive[1], "direction": directive[2],
                "address_family": family, "source_line": number,
            })
        elif directive[:1] == ["send-community"] and len(directive) <= 2:
            n["send_community_by_family"][family or "global"] = (
                directive[1] if len(directive) == 2 else "standard"
            )
        elif directive == ["advertise", "additional-paths", "all"]:
            n["advertise_additional_paths"].append({"address_family": family, "selection": "all"})
        elif directive == ["route-reflector-client"]:
            key = family or "global"
            if key not in n["route_reflector_client_families"]:
                n["route_reflector_client_families"].append(key)
    elif tokens and tokens[0] == "network" and len(tokens) >= 2:
        mask = tokens[tokens.index("mask") + 1] if "mask" in tokens and tokens.index("mask") + 1 < len(tokens) else None
        bgp["network_statements"].append({
            "prefix": tokens[1], "mask": mask,
            "address_family": family, "source_line": number,
            "raw": command,
        })
    else:
        if family:
            for af in bgp["address_families"]:
                if af["name"] == family:
                    af["other_commands"].append(command)
                    return
        bgp["other_commands"].append(command)


def parse_cisco_ios(content: str) -> dict:
    """Return a source-faithful structured extraction, never an inferred network state."""
    source_lines = content.splitlines()
    explicit_xr = any("IOS XR Configuration" in line for line in source_lines[:40])
    xr_style = (any(line.strip() == "router static" for line in source_lines)
                and any(line.strip().startswith("interface MgmtEth") for line in source_lines))
    result = {
        "vendor": "cisco_ios", "parser_schema_version": "6.0",
        "source_cli_family": ("ios_xr" if explicit_xr else
                              "ios_xr_candidate" if xr_style else "ios"),
        "hostname": None, "interfaces": [],
        "ospf_processes": [], "eigrp_processes": [], "static_routes": [], "bgp_processes": [],
        "key_chains": [],
        "access_lists": [], "prefix_lists": [], "route_maps": [],
        "community_lists": [], "wrapper_commands": [], "unparsed_lines": [],
        "vrfs": [],
        "global_settings": {
            "ios_version": None, "ip_domain_name": None,
            "ip_domain_lookup_enabled": None, "ip_cef_enabled": None,
            "ipv6_cef_enabled": None, "service_timestamps": [],
            "service_commands": [], "ssh_commands": [],
            "http_server_enabled": None, "https_server_enabled": None,
            "spanning_tree_mode": None, "spanning_tree_extend_system_id": None,
            "cdp_enabled": None, "ip_forward_protocols": [],
            "tftp_source_interface": None, "dns_views": [],
            "ipv6_ioam_commands": [],
            "enable_secret_configured": None, "enable_password_configured": None,
            "rsa_key_generation_requests": [], "aaa_login_privilege_mode": None,
            "aaa_authentication_login": [], "aaa_authentication_enable": [],
            "bgp_community_new_format": None,
            "icmp_unreachable_rate_limit": None, "tcp_synwait_seconds": None,
            "ip_source_route_enabled": None,
            "clock_timezone": None,
        },
        "ntp": {
            "servers": [], "peers": [], "source_interface": None,
            "authentication_enabled": None, "authentication_keys": [],
            "trusted_key_ids": [], "master_configured": None,
            "master_stratum": None, "access_groups": [],
            "update_calendar_enabled": None, "logging_enabled": None,
            "clock_period": None,
        },
        "configuration_metadata": [], "platform_commands": [],
        "local_users": [], "lines": [], "banners": [], "system_stanzas": [],
        "vlans": [], "dhcp_pools": [], "dhcp_excluded_addresses": [],
        "dhcp_other_commands": [], "nat_rules": [], "nat_pools": [],
        "nat_other_commands": [], "nat_translation_settings": {},
        "snmp": {"communities": [], "hosts": [], "groups": [], "users": [],
                 "trap_rules": [], "traps_enabled": None,
                 "location_configured": None, "contact_configured": None,
                 "other_commands": []},
        "syslog": {"hosts": [], "source_interface": None,
                   "trap_level": None, "console_enabled": None, "buffered": None,
                   "other_commands": []},
    }
    context = None
    current = None
    current_family = None

    for number, raw in enumerate(content.splitlines(), 1):
        cmd = raw.strip()
        if not cmd:
            continue
        indented = raw[0].isspace()

        # IOS banner bodies are opaque text, not executable configuration.
        # Some IOSv exports use ^C as the delimiter, including a closing ^C
        # at the end of a banner's last text line.
        if context == "banner":
            current["body_lines"].append(raw)
            if current["delimiter"] in cmd:
                context, current, current_family = None, None, None
            continue

        # In IOS BGP a *nested*, indented '!' separates neighbor and AF sections.
        if cmd.startswith("!"):
            if cmd == "!" and not indented:
                context, current, current_family = None, None, None
            continue
        if cmd in WRAPPER_COMMANDS:
            result["wrapper_commands"].append({"line": number, "command": cmd})
            if cmd in ("exit", "end"):
                if cmd == "exit" and context == "bgp" and current_family:
                    current_family = None
                else:
                    context, current, current_family = None, None, None
            continue
        if cmd == "exit-address-family":
            current_family = None
            continue
        if cmd == "exit-af-interface" and context == "eigrp":
            current["active_af_interface"] = None
            continue

        # Some real exported scripts omit indentation after `line con 0`.
        # Recover only this exact *line-mode* command, and record the repair;
        # never generalize this to arbitrary unindented commands.
        if not indented and context == "line" and cmd == "logging synchronous":
            _parse_line_command(current, cmd)
            result.setdefault("formatting_recoveries", []).append({
                "line": number, "scope": "line", "family": "logging synchronous",
            })
            continue

        # A new top-level IOS command normally closes the prior stanza.
        if not indented:
            context, current, current_family = None, None, None

            if cmd == "Building configuration..." or cmd.startswith("Current configuration :"):
                result["configuration_metadata"].append(cmd)
                continue
            if cmd.startswith("hostname "):
                result["hostname"] = cmd[9:].strip()
                continue
            if cmd.startswith("version "):
                result["global_settings"]["ios_version"] = cmd[8:].strip()
                continue
            if cmd.startswith("ip domain name "):
                result["global_settings"]["ip_domain_name"] = cmd[len("ip domain name "):]
                continue
            if cmd in ("no ip domain lookup", "no ip domain-lookup"):
                result["global_settings"]["ip_domain_lookup_enabled"] = False
                continue
            if cmd in ("ip domain lookup", "ip domain-lookup"):
                result["global_settings"]["ip_domain_lookup_enabled"] = True
                continue
            if cmd in ("ip cef", "no ip cef"):
                result["global_settings"]["ip_cef_enabled"] = cmd == "ip cef"
                continue
            if cmd in ("ipv6 cef", "no ipv6 cef"):
                result["global_settings"]["ipv6_cef_enabled"] = cmd == "ipv6 cef"
                continue
            if cmd.startswith("service timestamps "):
                result["global_settings"]["service_timestamps"].append(cmd)
                continue
            if cmd.startswith("service ") or cmd.startswith("no service "):
                result["global_settings"]["service_commands"].append(cmd)
                continue
            if cmd.startswith("username "):
                account = _account(cmd, number)
                if account is not None:
                    result["local_users"].append(account)
                continue
            if cmd in ("aaa new-model", "no aaa new-model"):
                result["global_settings"]["aaa_new_model_enabled"] = cmd == "aaa new-model"
                continue
            if cmd.startswith("aaa authentication login "):
                p = cmd.split()
                if len(p) >= 5:
                    result["global_settings"]["aaa_authentication_login"].append({
                        "name": p[3], "methods": p[4:], "source_line": number,
                    })
                continue
            if cmd.startswith("aaa authentication enable "):
                p = cmd.split()
                if len(p) >= 5:
                    result["global_settings"]["aaa_authentication_enable"].append({
                        "name": p[3], "methods": p[4:], "source_line": number,
                    })
                continue
            if cmd.startswith("key chain "):
                current = {"name": cmd[len("key chain "):], "source_line": number,
                           "key_ids": [], "key_string_key_ids": [], "other_count": 0}
                result["key_chains"].append(current)
                context = "key_chain"
                continue
            if cmd in ("logging console", "no logging console"):
                result["syslog"]["console_enabled"] = cmd == "logging console"
                continue
            if cmd in ("ip http server", "no ip http server"):
                result["global_settings"]["http_server_enabled"] = cmd == "ip http server"
                continue
            if cmd in ("ip http secure-server", "no ip http secure-server"):
                result["global_settings"]["https_server_enabled"] = cmd == "ip http secure-server"
                continue
            if cmd.startswith("ip ssh "):
                result["global_settings"]["ssh_commands"].append(cmd)
                continue
            if cmd.startswith("ip forward-protocol "):
                result["global_settings"]["ip_forward_protocols"].append(cmd[len("ip forward-protocol "):])
                continue
            if cmd.startswith("ip tftp source-interface "):
                result["global_settings"]["tftp_source_interface"] = cmd[len("ip tftp source-interface "):]
                continue
            if cmd.startswith("ip dns view "):
                result["global_settings"]["dns_views"].append(cmd[len("ip dns view "):])
                continue
            if cmd.startswith("ipv6 ioam "):
                result["global_settings"]["ipv6_ioam_commands"].append(cmd)
                continue
            if cmd.startswith("spanning-tree mode "):
                result["global_settings"]["spanning_tree_mode"] = cmd[len("spanning-tree mode "):]
                continue
            if cmd == "spanning-tree extend system-id":
                result["global_settings"]["spanning_tree_extend_system_id"] = True
                continue
            if cmd in ("cdp run", "no cdp run"):
                result["global_settings"]["cdp_enabled"] = cmd == "cdp run"
                continue
            if cmd.startswith("line "):
                current = {
                    "identifier": cmd[len("line "):], "source_line": number,
                    "exec_timeout": None, "login_method": None,
                    "access_classes": [],
                    "privilege_level": None, "stopbits": None,
                    "transport_input": [], "transport_output": [],
                    "logging_synchronous": False, "password_configured": False,
                    "other_commands": [],
                }
                result["lines"].append(current)
                context = "line"
                continue
            if cmd.startswith("banner "):
                p = cmd.split(maxsplit=2)
                if len(p) == 3:
                    marker = p[2]
                    delimiter = "^C" if marker.startswith("^C") else marker[0]
                    current = {"kind": p[1], "source_line": number,
                               "delimiter": delimiter, "opening_command": cmd,
                               "body_lines": []}
                    result["banners"].append(current)
                    # A complete one-line banner, e.g. ^CMessage^C, must
                    # not swallow following console/VTY stanzas.
                    body_after_opening = marker[len(delimiter):]
                    context = None if delimiter in body_after_opening else "banner"
                    continue
            if cmd in ("redundancy", "control-plane"):
                current = {"name": cmd, "source_line": number, "commands": []}
                result["system_stanzas"].append(current)
                context = "system_stanza"
                continue
            if cmd in {"boot-start-marker", "boot-end-marker"} or cmd.startswith((
                "mmi ", "no mmi ", "no process ", "multilink ",
                "no scheduler ", "scheduler ", "service-routing ",
                "no service-routing ",
            )):
                result["platform_commands"].append({
                    "source_line": number, "command": cmd,
                    "structured": _platform_directive(cmd),
                })
                continue
            if cmd.startswith(("vrf definition ", "ip vrf ")):
                name = cmd.split(maxsplit=2)[-1]
                current = _get_named(
                    result["vrfs"], name, source_line=number,
                    description=None, rd=None, address_families=[],
                    route_targets=[], other_commands=[],
                )
                context = "vrf"
                continue
            if cmd.startswith("interface "):
                current = {
                    "name": cmd[10:].strip(), "source_line": number,
                    "ipv4_addresses": [], "no_ip_address": False,
                    "ipv4_dhcp": False, "ipv4_dhcp_options": [],
                    "mtu": None, "acl_bindings": [], "ospf_network_type": None,
                    "ospf_md5_keys": [], "ospf_authentication_mode": None,
                    "eigrp_authentication": {},
                    "vrf_forwarding": None,
                    "description": None, "duplex": None, "speed": None,
                    "media_type": None, "negotiation": None,
                    "cdp_enabled": None,
                    "administrative_command": None, "other_commands": [],
                    "ip_helper_addresses": [], "nat_role": None,
                    "switchport": {"mode": None, "access_vlan": None,
                                   "native_vlan": None, "allowed_vlan_commands": [],
                                   "trunk_encapsulation": None},
                    "dot1q": None, "hsrp_version": None, "hsrp_groups": [],
                }
                result["interfaces"].append(current)
                context = "interface"
                continue
            if cmd.startswith("router ospf "):
                parts = cmd.split()
                if len(parts) == 3:
                    current = {
                        "process_id": parts[2], "source_line": number,
                        "router_id": None, "networks": [], "passive_interfaces": [],
                        "area_authentication": [],
                        "non_passive_interfaces": [],
                        "redistribution_commands": [], "other_commands": [],
                        "default_information_originate": None,
                        "default_information_options": [],
                    }
                    result["ospf_processes"].append(current)
                    context = "ospf"
                    continue
            if cmd.startswith("router eigrp "):
                current = {"identifier": cmd[len("router eigrp "):], "source_line": number,
                           "address_families": [], "networks": [], "passive_interfaces": [],
                           "af_interfaces": {}, "active_af_interface": None,
                           "auto_summary_enabled": None,
                           "other_count": 0}
                result["eigrp_processes"].append(current)
                context = "eigrp"
                continue
            if cmd.startswith("router bgp "):
                parts = cmd.split()
                if len(parts) == 3:
                    current = {
                        "local_as": parts[2], "source_line": number,
                        "router_id": None, "neighbors": [], "network_statements": [],
                        "address_families": [], "other_commands": [],
                        "log_neighbor_changes": None,
                    }
                    result["bgp_processes"].append(current)
                    context = "bgp"
                    continue
            if cmd.startswith("ip route "):
                route = _static_route(cmd, number)
                if route:
                    result["static_routes"].append(route)
                else:
                    _record_unknown(result, number, cmd)
                continue
            if cmd.startswith("vlan "):
                current = _get_named(result["vlans"], cmd[5:].strip(),
                                     configured_name=None, other_commands=[])
                context = "vlan"
                continue
            if cmd.startswith("ip dhcp pool "):
                current = _get_named(result["dhcp_pools"], cmd[len("ip dhcp pool "):].strip(),
                                     network=None, default_routers=[], dns_servers=[],
                                     domain_name=None, lease=None, other_commands=[])
                context = "dhcp_pool"
                continue
            if cmd.startswith("ip dhcp excluded-address "):
                result["dhcp_excluded_addresses"].append({
                    "addresses": cmd.split()[3:], "source_line": number,
                })
                continue
            if cmd.startswith("ip dhcp "):
                result["dhcp_other_commands"].append(cmd)
                continue
            if cmd.startswith("ip nat translation "):
                p = cmd.split()
                if (len(p) == 5 and p[3] in {"icmp-timeout", "tcp-timeout", "udp-timeout"}
                        and p[4].isdecimal()):
                    result["nat_translation_settings"][p[3].replace("-", "_") + "_seconds"] = int(p[4])
                else:
                    result["nat_other_commands"].append(cmd)
                continue
            if _nat_global(result, cmd, number):
                continue
            if _snmp_syslog_global(result, cmd, number):
                continue
            if cmd.startswith("access-list "):
                parts = cmd.split(maxsplit=2)
                if len(parts) == 3:
                    acl = _get_named(result["access_lists"], parts[1],
                                     acl_type="numbered", entries=[], other_commands=[])
                    acl["entries"].append(_acl_entry(parts[2], number))
                else:
                    _record_unknown(result, number, cmd)
                continue
            if cmd.startswith("ip access-list "):
                parts = cmd.split(maxsplit=3)
                if len(parts) == 4:
                    current = _get_named(result["access_lists"], parts[3],
                                         acl_type=parts[2], entries=[], other_commands=[])
                    context = "acl"
                else:
                    _record_unknown(result, number, cmd)
                continue
            if cmd.startswith("ip prefix-list "):
                parsed = _prefix_list(cmd, number)
                if parsed:
                    name, entry = parsed
                    item = _get_named(result["prefix_lists"], name, entries=[])
                    item["entries"].append(entry)
                else:
                    _record_unknown(result, number, cmd)
                continue
            if cmd.startswith("ip community-list "):
                parts = cmd.split(maxsplit=4)
                if len(parts) == 5:
                    name = parts[3]
                    item = _get_named(result["community_lists"], name,
                                      community_type=parts[2], entries=[])
                    item["entries"].append({
                        "raw": cmd, "definition": parts[4], "source_line": number,
                    })
                else:
                    _record_unknown(result, number, cmd)
                continue
            if cmd.startswith("route-map "):
                parts = cmd.split()
                if len(parts) >= 4:
                    group = _get_named(result["route_maps"], parts[1], entries=[])
                    current = {
                        "action": parts[2], "sequence": parts[3],
                        "source_line": number, "match_commands": [],
                        "set_commands": [], "other_commands": [],
                    }
                    group["entries"].append(current)
                    context = "route_map"
                else:
                    _record_unknown(result, number, cmd)
                continue

            if not _parse_global_extension(result, cmd, number):
                _record_unknown(result, number, cmd)
            continue

        if context == "interface":
            if cmd == "ip address dhcp" or cmd.startswith("ip address dhcp "):
                current["ipv4_dhcp"] = True
                current["ipv4_dhcp_options"] = cmd.split()[3:]
            elif cmd.startswith("ip address "):
                p = cmd.split()
                if len(p) >= 4:
                    current["ipv4_addresses"].append({
                        "address": p[2], "mask": p[3], "options": p[4:],
                    })
                else:
                    current["other_commands"].append(cmd)
            elif cmd == "no ip address":
                current["no_ip_address"] = True
            elif cmd in ("shutdown", "no shutdown"):
                current["administrative_command"] = cmd
            elif _interface_extension(current, cmd):
                pass
            else:
                current["other_commands"].append(cmd)
        elif context == "ospf":
            p = cmd.split()
            if len(p) == 2 and p[0] == "router-id":
                current["router_id"] = p[1]
            elif len(p) == 5 and p[0] == "network" and p[3] == "area":
                current["networks"].append({
                    "network": p[1], "wildcard_mask": p[2], "area": p[4],
                })
            elif len(p) == 2 and p[0] == "passive-interface":
                current["passive_interfaces"].append(p[1])
            elif len(p) == 4 and p[0] == "area" and p[2:] == ["authentication", "message-digest"]:
                current["area_authentication"].append({"area": p[1], "mode": "message-digest"})
            elif len(p) == 3 and p[0] == "area" and p[2] == "authentication":
                current["area_authentication"].append({"area": p[1], "mode": "plain"})
            elif (len(p) in (3, 4) and p[:2] == ["no", "passive-interface"]
                  and p[2] != "default"):
                # Explicit exception, especially after passive-interface default.
                # Preserve declarations; do not infer effective link/OSPF state.
                current["non_passive_interfaces"].append(" ".join(p[2:]))
            elif p[:2] == ["default-information", "originate"]:
                current["default_information_originate"] = True
                current["default_information_options"] = p[2:]
            elif cmd.startswith("redistribute "):
                current["redistribution_commands"].append(cmd)
            else:
                current["other_commands"].append(cmd)
        elif context == "eigrp":
            p = cmd.split()
            if p[:2] == ["address-family", "ipv4"] and "autonomous-system" in p:
                index = p.index("autonomous-system")
                if len(p) > index + 1:
                    current["address_families"].append({"family": "ipv4", "as": p[index + 1]})
            elif p[:1] == ["af-interface"] and len(p) == 2:
                current["active_af_interface"] = p[1]
                current["af_interfaces"].setdefault(p[1], {})
            elif p[:2] == ["authentication", "mode"] and len(p) == 3 and current["active_af_interface"]:
                current["af_interfaces"][current["active_af_interface"]]["mode"] = p[2]
            elif p[:2] == ["authentication", "key-chain"] and len(p) == 3 and current["active_af_interface"]:
                current["af_interfaces"][current["active_af_interface"]]["key_chain"] = p[2]
            elif p[:1] == ["network"] and len(p) >= 2:
                current["networks"].append(p[1:])
            elif p[:1] == ["passive-interface"] and len(p) == 2:
                current["passive_interfaces"].append(p[1])
            elif p == ["no", "auto-summary"]:
                current["auto_summary_enabled"] = False
            elif p == ["auto-summary"]:
                current["auto_summary_enabled"] = True
            else:
                current["other_count"] += 1
        elif context == "key_chain":
            p = cmd.split()
            if len(p) == 2 and p[0] == "key":
                current["key_ids"].append(p[1])
            elif p[:1] == ["key-string"]:
                if current["key_ids"]:
                    current["key_string_key_ids"].append(current["key_ids"][-1])
            else:
                # Secret-bearing key lifetimes/commands are never copied verbatim.
                current["other_count"] += 1
        elif context == "bgp":
            if cmd.startswith("address-family "):
                current_family = cmd[len("address-family "):]
                if not any(af["name"] == current_family for af in current["address_families"]):
                    current["address_families"].append({
                        "name": current_family, "source_line": number,
                        "other_commands": [], "dampening_configured": None,
                        "additional_paths_commands": [], "maximum_paths_eibgp": None,
                        "aggregate_addresses": [],
                    })
            else:
                _parse_bgp_line(current, cmd, number, current_family)
        elif context == "acl":
            current["entries"].append(_acl_entry(cmd, number))
        elif context == "route_map":
            if cmd.startswith("match "):
                current["match_commands"].append(cmd)
            elif cmd.startswith("set "):
                current["set_commands"].append(cmd)
            else:
                current["other_commands"].append(cmd)
        elif context == "vrf":
            if cmd.startswith("description "):
                current["description"] = cmd[len("description "):]
            elif cmd.startswith("rd "):
                current["rd"] = cmd[3:].strip()
            elif cmd.startswith("address-family "):
                family = cmd[len("address-family "):]
                if family not in current["address_families"]:
                    current["address_families"].append(family)
            elif cmd.startswith("route-target "):
                current["route_targets"].append(cmd[len("route-target "):])
            else:
                current["other_commands"].append(cmd)
        elif context == "line":
            if not _parse_line_command(current, cmd):
                current["other_commands"].append(cmd)
        elif context == "system_stanza":
            current["commands"].append(cmd)
        elif context == "vlan":
            if cmd.startswith("name "):
                current["configured_name"] = cmd[5:]
            else:
                current["other_commands"].append(cmd)
        elif context == "dhcp_pool":
            p = cmd.split()
            if len(p) >= 3 and p[0] == "network":
                current["network"] = {"address": p[1], "mask_or_prefix": p[2]}
            elif len(p) >= 2 and p[0] == "default-router":
                current["default_routers"].extend(p[1:])
            elif len(p) >= 2 and p[0] == "dns-server":
                current["dns_servers"].extend(p[1:])
            elif len(p) >= 2 and p[0] == "domain-name":
                current["domain_name"] = " ".join(p[1:])
            elif p == ["lease", "infinite"]:
                current["lease"] = {"infinite": True, "duration_seconds": None,
                                    "source_line": number}
            elif (2 <= len(p) <= 4 and p[0] == "lease"
                  and all(part.isdecimal() for part in p[1:])
                  and (len(p) < 3 or int(p[2]) <= 23)
                  and (len(p) < 4 or int(p[3]) <= 59)):
                duration = (int(p[1]) * 86400 +
                            (int(p[2]) * 3600 if len(p) >= 3 else 0) +
                            (int(p[3]) * 60 if len(p) >= 4 else 0))
                if duration > 0:
                    current["lease"] = {"infinite": False, "duration_seconds": duration,
                                        "source_line": number}
                else:
                    current["other_commands"].append(cmd)
            elif p == ["no", "lease"]:
                current["lease"] = None
            else:
                current["other_commands"].append(cmd)
        else:
            _record_unknown(result, number, cmd)

    _complete_bgp(result)
    return result


def _summary(parsed: dict, label: str) -> str:
    return (
        f"{label}: hostname={parsed['hostname']}, "
        f"interfaces={len(parsed['interfaces'])}, "
        f"VRFs={len(parsed['vrfs'])}, "
        f"OSPF={len(parsed['ospf_processes'])}, "
        f"BGP={len(parsed['bgp_processes'])}, "
        f"routes={len(parsed['static_routes'])}, "
        f"ACL={len(parsed['access_lists'])}, "
        f"prefix-lists={len(parsed['prefix_lists'])}, "
        f"route-maps={len(parsed['route_maps'])}, "
        f"NAT={len(parsed['nat_rules'])}, "
        f"VLANs={len(parsed['vlans'])}, "
        f"DHCP-relays={sum(len(i['ip_helper_addresses']) for i in parsed['interfaces'])}, "
        f"HSRP={sum(len(i['hsrp_groups']) for i in parsed['interfaces'])}, "
        f"SNMP={len(parsed['snmp']['communities']) + len(parsed['snmp']['hosts'])}, "
        f"Syslog={len(parsed['syslog']['hosts'])}, "
        f"lignes_console_vty={len(parsed['lines'])}, "
        f"bannieres={len(parsed['banners'])}, "
        f"comptes_locaux={len(parsed['local_users'])}, "
        f"directives_plateforme_brutes={len(parsed['platform_commands'])}, "
        f"globales non analysées={len(parsed['unparsed_lines'])}"
    )


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(description="Parseur ciblé Cisco IOS / CLI.")
    cli.add_argument("source", type=Path, help="Fichier .cfg/.txt ou dossier")
    cli.add_argument("--output-dir", type=Path, help="Dossier pour les JSON exportés")
    cli.add_argument("--json-only", action="store_true", help="JSON pur sur stdout (fichier unique)")
    args = cli.parse_args(argv)
    if not args.source.exists():
        cli.error(f"Source introuvable : {args.source}")
    if args.source.is_dir():
        paths = sorted(p for p in args.source.rglob("*")
                       if p.is_file() and p.suffix.lower() in (".cfg", ".txt"))
        if args.json_only:
            cli.error("--json-only est réservé au fichier unique")
    else:
        paths = [args.source]
    if not paths:
        cli.error("Aucun fichier .cfg ou .txt trouvé")

    for path in paths:
        try:
            data = parse_cisco_ios(path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError) as exc:
            print(f"Erreur lecture {path}: {exc}", file=sys.stderr)
            return 1
        data["source_file"] = path.name
        if args.output_dir:
            relative = path.relative_to(args.source) if args.source.is_dir() else Path(path.name)
            target = args.output_dir / relative.with_suffix(".json")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        if len(paths) == 1:
            print(json.dumps(data, ensure_ascii=False, indent=2))
        if not args.json_only:
            print(_summary(data, str(path)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
