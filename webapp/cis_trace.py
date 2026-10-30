"""Secret-safe source provenance and contextual, read-only verification hints.

Only the normalized IR and CIS evidence are inspected. A stanza's source line
is labelled as its *start*, never presented as the exact offending directive.
No raw IOS commands, credentials or SNMP community strings are exported.
"""

from __future__ import annotations

import re


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,89}\Z")


def _cli_name(value: object) -> str | None:
    """Allow a Cisco identifier in a displayed command, never shell syntax."""
    if isinstance(value, str) and _IDENTIFIER.fullmatch(value):
        return value
    return None


def _source_line(obj: object) -> int | None:
    if not isinstance(obj, dict):
        return None
    source = obj.get("source")
    value = source.get("line") if isinstance(source, dict) else obj.get("source_line")
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 < value < 1000000 else None


def enhance_trace(finding: dict, check: str, ir: dict | None, *,
                  external_interfaces: list[str] | None = None) -> None:
    """Annotate a finding with source-line anchors and verification commands.

    Does not evaluate any rule or change statuses/evidence.
    """
    if not isinstance(ir, dict):
        return
    management = ir.get("management") or {}
    services = ir.get("services") or {}
    routing = ir.get("routing") or {}
    policies = ir.get("policies") or {}
    interfaces = ir.get("interfaces") or []
    lines = management.get("terminal_lines") or []
    acl_defs = {a.get("name"): a for a in policies.get("acls") or [] if isinstance(a, dict)}
    anchors: list[dict] = []

    def add(obj: object, name: str, kind: str = "début de bloc") -> None:
        number = _source_line(obj)
        if number is not None and len(anchors) < 30:
            item = {"line": number, "element": name, "scope": kind}
            if item not in anchors:
                anchors.append(item)

    def acl_entries(name: object) -> None:
        identifier = _cli_name(name)
        if identifier and identifier in acl_defs:
            for entry in acl_defs[identifier].get("entries") or []:
                add(entry, f"ACL {identifier}", "ligne de règle ACL")

    def terminal(prefix: str, include_acl: bool = False) -> None:
        for line in lines:
            if str(line.get("line_id", "")).startswith(prefix):
                add(line, f"ligne {line['line_id']}")
                if include_acl:
                    for binding in line.get("access_classes") or []:
                        if binding.get("direction") == "in":
                            acl_entries(binding.get("acl"))

    def selected_wan() -> list[dict]:
        selected = set(external_interfaces or [])
        return [item for item in interfaces if item.get("name") in selected]

    def inbound_names() -> list[str]:
        names = []
        for interface in selected_wan():
            for binding in interface.get("acl_bindings") or []:
                if binding.get("direction") == "in":
                    name = _cli_name(binding.get("name"))
                    if name and name not in names:
                        names.append(name)
        return names

    def lines_to_show(commands: list[str], fallback: str) -> str:
        return "\n".join(list(dict.fromkeys(commands))[:8]) if commands else fallback

    verify = finding.get("verification_command", "show running-config")
    if check in {"vty_ssh_only", "vty_exec_timeout", "aaa_line_vty"}:
        terminal("vty ")
    elif check in {"console_exec_timeout", "aaa_line_console"}:
        terminal("con ")
    elif check == "aaa_line_tty":
        terminal("tty ")
    elif check in {"vty_restricting_acl", "vty_access_class"}:
        terminal("vty ", include_acl=True)
        acl_names = [
            _cli_name(binding.get("acl"))
            for line in lines if str(line.get("line_id", "")).startswith("vty ")
            for binding in line.get("access_classes") or []
            if binding.get("direction") == "in"
        ]
        commands = [f"show ip access-lists {name}" for name in acl_names if name]
        if check == "vty_access_class":
            commands.insert(0, "show running-config | section line vty")
        verify = lines_to_show(commands, "show ip access-lists")
    elif check in {"external_antispoof_acl", "external_inbound_acl"}:
        for interface in selected_wan():
            add(interface, f"interface {interface.get('name')}")
        for name in inbound_names():
            acl_entries(name)
        names = inbound_names()
        if check == "external_antispoof_acl":
            verify = lines_to_show([f"show ip access-lists {name}" for name in names],
                                   "show ip access-lists")
        else:
            commands = [f"show ip interface {name}" for name in (
                _cli_name(item.get("name")) for item in selected_wan()) if name]
            commands.extend(f"show ip access-lists {name}" for name in names)
            verify = lines_to_show(commands, "show ip interface")
    elif check == "proxy_arp_disabled":
        inspected = [item for item in interfaces if item.get("proxy_arp_enabled") is not None]
        for item in inspected:
            add(item, f"interface {item.get('name')}")
        verify = lines_to_show([
            f"show ip interface {name}" for name in (
                _cli_name(item.get("name")) for item in inspected) if name], "show ip interface")
    elif check == "no_tunnel_interfaces":
        for item in interfaces:
            if str(item.get("name", "")).lower().startswith("tunnel"):
                add(item, f"interface {item.get('name')}")
    elif check == "local_user_secrets":
        for item in management.get("local_accounts") or []:
            add(item, "compte local", "ligne de directive")
    elif check in {"aaa_login_default", "aaa_enable_default"}:
        key = "aaa_authentication_login" if check == "aaa_login_default" else "aaa_authentication_enable"
        for item in management.get(key) or []:
            if item.get("name") == "default":
                add(item, f"méthode {key}", "ligne de directive")
    elif check in {"exec_banner_present", "login_banner", "motd_banner"}:
        for item in management.get("banners") or []:
            add(item, "bannière de connexion")
    elif check in {"snmp_no_rw", "snmp_v3_priv"}:
        key = "communities" if check == "snmp_no_rw" else "groups"
        for item in (services.get("snmp") or {}).get(key) or []:
            # Community names and values must never appear in labels.
            add(item, "configuration SNMP", "ligne de directive")
    elif check in {"syslog_host", "syslog_buffer", "syslog_informational", "syslog_source_present"}:
        syslog = services.get("syslog") or {}
        related = {
            "syslog_host": ("targets",),
            "syslog_buffer": ("buffered",),
            "syslog_informational": ("severity",),
            "syslog_source_present": ("source_interface",),
        }
        for key in related[check]:
            value = syslog.get(key)
            if isinstance(value, list):
                for item in value:
                    add(item, "directive Syslog", "ligne de directive")
            else:
                add(value, "directive Syslog", "ligne de directive")
    elif check in {"ntp_servers", "ntp_server_keys", "ntp_auth_keys", "ntp_trusted_keys"}:
        ntp = services.get("ntp") or {}
        for item in ntp.get("servers") or []:
            add(item, "serveur NTP", "ligne de directive")
    elif check in {"eigrp_interface_keychain", "eigrp_interface_md5"}:
        involved = [item for item in interfaces if item.get("eigrp_authentication")]
        for item in involved:
            add(item, f"interface {item.get('name')}")
        for item in routing.get("eigrp") or []:
            add(item, "processus EIGRP")
    elif check in {"ospf_area_md5", "ospf_interface_md5"}:
        for item in routing.get("ospf") or []:
            add(item, "processus OSPF")
        for item in interfaces:
            if item.get("ospf_authentication_mode") is not None or item.get("ospf_md5_key_ids"):
                add(item, f"interface {item.get('name')}")
    elif check == "bgp_neighbor_password":
        for item in routing.get("bgp") or []:
            add(item, "processus BGP")
            for peer in item.get("neighbors") or []:
                add(peer, "voisin BGP")

    anchors.sort(key=lambda anchor: (anchor["line"], anchor["element"]))
    finding["source_anchors"] = anchors
    if anchors:
        presentation = "; ".join(
            f"{anchor['element']} : ligne {anchor['line']} ({anchor['scope']})"
            for anchor in anchors[:8])
        if len(anchors) > 8:
            presentation += f" ; +{len(anchors) - 8} repère(s) supplémentaire(s) dans le JSON"
        finding["source_location"] = presentation
    finding["verification_command"] = verify
