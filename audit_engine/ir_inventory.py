"""Inventaire sûr des capacités de parsing, normalisation et audit IOS.

Le module n'exporte que des chemins de schéma et des décomptes. Il ne copie
jamais les commandes sources : elles peuvent contenir des secrets.
"""

from __future__ import annotations

from collections import Counter
from typing import Any


# (groupe, nom, chemin parseur, chemin IR, contrôle CIS implémenté)
# Les champs de type dictionnaire représentent des sous-domaines, pas une
# preuve que chacune de leurs commandes a été interprétée sémantiquement.
_PARTS: tuple[tuple[str, str, str, str | None, str | None], ...] = (
    ("identite", "hostname", "hostname", "device.hostname", None),
    ("identite", "version_ios", "global_settings.ios_version", "device.platform.version", None),
    ("plateforme", "directives_plateforme", "platform_commands", "device.platform_directives", None),
    ("reseau", "vrf", "vrfs", "vrfs", None),
    ("reseau", "interfaces", "interfaces", "interfaces", None),
    ("reseau", "vlan", "vlans", "services.vlans", None),
    ("routage", "routes_statiques", "static_routes", "routing.static_routes", None),
    ("routage", "ospf", "ospf_processes", "routing.ospf", None),
    ("routage", "eigrp", "eigrp_processes", "routing.eigrp", None),
    ("routage", "chaines_cles", "key_chains", "routing.key_chains", None),
    ("routage", "bgp", "bgp_processes", "routing.bgp", None),
    ("politiques", "acl", "access_lists", "policies.acls", None),
    ("politiques", "prefix_lists", "prefix_lists", "policies.prefix_lists", None),
    ("politiques", "route_maps", "route_maps", "policies.route_maps", None),
    ("politiques", "community_lists", "community_lists", "policies.community_lists", None),
    ("services", "nat", "nat_rules", "services.nat.rules", None),
    ("services", "nat_pools", "nat_pools", "services.nat.pools", None),
    ("services", "nat_timers", "nat_translation_settings", "services.nat.translation_timers", None),
    ("services", "dhcp_pools", "dhcp_pools", "services.dhcp.pools", None),
    ("services", "dhcp_exclusions", "dhcp_excluded_addresses", "services.dhcp.excluded_ranges", None),
    ("supervision", "snmp_communities", "snmp.communities", "services.snmp.communities", None),
    ("supervision", "snmp_groups", "snmp.groups", "services.snmp.groups", None),
    ("supervision", "snmp_users", "snmp.users", "services.snmp.users", None),
    ("supervision", "snmp_targets", "snmp.hosts", "services.snmp.targets", None),
    ("supervision", "snmp_traps", "snmp.trap_rules", "services.snmp.trap_rules", None),
    ("supervision", "syslog_targets", "syslog.hosts", "services.syslog.targets", None),
    ("supervision", "syslog_source", "syslog.source_interface", "services.syslog.source_interface", "2.2.7"),
    ("supervision", "syslog_buffer", "syslog.buffered", "services.syslog.buffered", None),
    ("supervision", "syslog_severity", "syslog.trap_level", "services.syslog.severity", None),
    ("temps", "ntp_servers", "ntp.servers", "services.ntp.servers", None),
    ("temps", "ntp_peers", "ntp.peers", "services.ntp.peers", None),
    ("temps", "ntp_authentication", "ntp.authentication_enabled", "services.ntp.authentication_enabled", "2.3.1.1"),
    ("temps", "ntp_access_groups", "ntp.access_groups", "services.ntp.access_groups", None),
    ("temps", "ntp_source", "ntp.source_interface", "services.ntp.source_interface", None),
    ("temps", "timezone", "global_settings.clock_timezone", "services.clock.timezone", None),
    ("securite_ip", "ip_source_route", "global_settings.ip_source_route_enabled", "services.ip_stack.source_route_enabled", "3.1.1"),
    ("securite_ip", "icmp_rate_limit", "global_settings.icmp_unreachable_rate_limit", "services.ip_stack.icmp_unreachable_rate_limit", None),
    ("securite_ip", "tcp_synwait", "global_settings.tcp_synwait_seconds", "services.ip_stack.tcp_synwait_seconds", None),
    ("administration", "vty_et_console", "lines", "management.terminal_lines", "1.2.2"),
    ("administration", "comptes_locaux", "local_users", "management.local_accounts", None),
    ("administration", "bannieres", "banners", "management.banners", "1.3.1"),
    ("administration", "enable_secret", "global_settings.enable_secret_configured", "management.enable_secret_configured", "1.4.1"),
    ("administration", "enable_password", "global_settings.enable_password_configured", "management.enable_password_configured", None),
    ("administration", "http", "global_settings.http_server_enabled", "management.http_enabled", None),
    ("administration", "https", "global_settings.https_server_enabled", "management.https_enabled", None),
    ("administration", "ssh", "global_settings.ssh_commands", "management.ssh_version", None),
    ("administration", "aaa", "global_settings.aaa_login_privilege_mode", "management.aaa_login_privilege_mode", None),
    ("administration", "aaa_new_model", "global_settings.aaa_new_model_enabled", "management.aaa_new_model_enabled", None),
    ("administration", "aaa_login", "global_settings.aaa_authentication_login", "management.aaa_authentication_login", None),
    ("administration", "aaa_enable", "global_settings.aaa_authentication_enable", "management.aaa_authentication_enable", None),
    ("administration", "rsa_keys", "global_settings.rsa_key_generation_requests", "management.rsa_key_generation_requests", None),
    ("hors_ir", "metadonnees_config", "configuration_metadata", None, None),
    ("hors_ir", "stanzas_systeme", "system_stanzas", None, None),
    ("hors_ir", "cli_wrappers", "wrapper_commands", None, None),
    ("hors_ir", "service_timestamps", "global_settings.service_timestamps", None, None),
    ("hors_ir", "autres_services_globaux", "global_settings.service_commands", None, None),
    ("hors_ir", "nat_commandes_non_modelees", "nat_other_commands", None, None),
    ("hors_ir", "dhcp_commandes_non_modelees", "dhcp_other_commands", None, None),
    ("hors_ir", "commandes_globales_inconnues", "unparsed_lines", None, None),
)

_STRUCTURAL_PARSER_KEYS = {"vendor", "parser_schema_version", "source_cli_family", "global_settings", "snmp", "syslog", "ntp", "source_file", "formatting_recoveries"}


def _get(data: dict[str, Any], path: str) -> Any:
    value: Any = data
    for item in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(item)
    return value


def _count(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, (list, dict, tuple, set)):
        return len(value)
    if isinstance(value, str):
        return 1 if value.strip() else 0
    return 1


def build_ir_inventory(parsed: dict[str, Any], ir: dict[str, Any],
                       catalogue: dict[str, Any] | None = None) -> dict[str, Any]:
    """Lister les parties sources, leur projection IR et l'audit disponible."""
    if parsed.get("vendor") != "cisco_ios" or _get(ir, "source.vendor") != "cisco_ios":
        raise ValueError("L'inventaire nécessite un parsing et une IR Cisco IOS")

    by_part: dict[str, list[str]] = {}
    allowed_ids = None
    if catalogue is not None:
        allowed_ids = {rule.get("control_id") for rule in catalogue.get("rules", [])}
        for rule in catalogue.get("rules", []):
            part_name = rule.get("inventory_part")
            control_id = rule.get("control_id")
            if part_name and control_id and control_id not in by_part.setdefault(part_name, []):
                by_part[part_name].append(control_id)

    parts = []
    for group, name, parser_path, ir_path, rule in _PARTS:
        mapped_rules = list(by_part.get(name, []))
        if rule and (allowed_ids is None or rule in allowed_ids) and rule not in mapped_rules:
            mapped_rules.insert(0, rule)
        parsed_count = _count(_get(parsed, parser_path))
        ir_count = _count(_get(ir, ir_path)) if ir_path else 0
        if ir_path is None:
            status = "SOURCE_ONLY" if parsed_count else "NOT_PRESENT"
        elif parsed_count and not ir_count:
            status = "PARSER_TO_IR_GAP"
        elif mapped_rules:
            status = "AUDITED" if ir_count else "AUDITABLE_NOT_OBSERVED"
        else:
            status = "IR_MAPPED" if ir_count else "NOT_PRESENT"
        parts.append({
            "group": group, "part": name, "parser_path": parser_path,
            "ir_path": ir_path, "parser_count": parsed_count,
            "ir_count": ir_count, "cis_control_id": mapped_rules[0] if mapped_rules else None,
            "cis_control_ids": mapped_rules, "status": status,
        })

    diagnostics = ir.get("diagnostics") or {}
    opaque = diagnostics.get("opaque_sections") or []
    counts = Counter(part["status"] for part in parts)
    mapped_parser_roots = {row[2].split(".")[0] for row in _PARTS}
    unexplained_roots = sorted(set(parsed) - mapped_parser_roots - _STRUCTURAL_PARSER_KEYS)
    warnings = []
    if diagnostics.get("unparsed_global_count", 0):
        warnings.append("Commandes globales non interprétées : couverture non exhaustive")
    if opaque:
        warnings.append("Sous-commandes conservées comme opaques : revoir les sections signalées")
    if diagnostics.get("formatting_recovery_count", 0):
        warnings.append("Récupération de mise en forme : vérifier les frontières de sections")
    if unexplained_roots:
        warnings.append("Nouveaux domaines parseur non répertoriés dans l'inventaire")
    return {
        "part_count": len(parts),
        "group_count": len({part["group"] for part in parts}),
        "counts_by_status": dict(sorted(counts.items())),
        "audited_part_count": sum(1 for part in parts if part["cis_control_id"]),
        "mapped_cis_rule_count": len({c for part in parts for c in part["cis_control_ids"]}),
        "unparsed_global_count": diagnostics.get("unparsed_global_count", 0),
        "opaque_command_count": sum(int(item.get("count") or 0) for item in opaque if isinstance(item, dict)),
        "opaque_scopes": sorted({str(item.get("section")) for item in opaque if isinstance(item, dict)}),
        "unaccounted_parser_roots": unexplained_roots,
        "warnings": warnings,
        "parts": parts,
    }
