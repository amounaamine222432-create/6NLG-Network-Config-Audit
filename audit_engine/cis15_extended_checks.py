"""Contrôles CIS IOS 15 complémentaires exploitant exclusivement l'IR.

Chaque retour distingue les preuves explicites des absences supposées.
Les sorties ne contiennent aucune commande brute ni valeur de secret.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable


def _get(ir: dict, *path: str) -> Any:
    value: Any = ir
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _missing(complete: bool, detail: dict | None = None) -> tuple[str, dict]:
    evidence = dict(detail or {})
    if complete:
        evidence["inferred_absence"] = True
    return ("FAIL" if complete else "UNKNOWN"), evidence


def _bool(ir: dict, complete: bool, *path: str) -> tuple[str, dict]:
    value = _get(ir, *path)
    if value is None:
        return _missing(complete, {"ir_path": ".".join(path), "observed": None})
    if type(value) is not bool:
        return "UNKNOWN", {"ir_path": ".".join(path), "observed_type": type(value).__name__}
    return ("PASS" if value else "FAIL"), {"ir_path": ".".join(path), "observed": value}


def _banner(ir: dict, complete: bool, kind: str) -> tuple[str, dict]:
    banners = _get(ir, "management", "banners")
    if not isinstance(banners, list):
        return "UNKNOWN", {"banner_kind": kind}
    found = [b for b in banners if isinstance(b, dict) and b.get("kind") == kind]
    if found:
        return "PASS", {"banner_kind": kind, "source_lines": [
            (b.get("source") or {}).get("line") for b in found
        ]}
    return _missing(complete, {"banner_kind": kind, "observed": False})


def _line_timeout(ir: dict, _complete: bool, scope: str) -> tuple[str, dict]:
    lines = _get(ir, "management", "terminal_lines")
    if not isinstance(lines, list):
        return "UNKNOWN", {"scope": scope, "lines": []}
    selected = [l for l in lines if isinstance(l, dict) and
                str(l.get("line_id") or "").lower().startswith(scope)]
    if not selected:
        return "UNKNOWN", {"scope": scope, "lines": []}
    statuses, evidence = [], []
    for line in selected:
        timeout = line.get("exec_timeout")
        status, seconds = "UNKNOWN", None
        if (isinstance(timeout, list) and 1 <= len(timeout) <= 2
                and all(str(x).isdecimal() for x in timeout)):
            minutes = int(timeout[0])
            remainder = int(timeout[1]) if len(timeout) == 2 else 0
            if remainder < 60:
                seconds = minutes * 60 + remainder
                status = "PASS" if 0 < seconds <= 600 else "FAIL"
        # L'absence de commande peut correspondre à la valeur IOS par défaut.
        # Ne jamais convertir cette absence en FAIL sans preuve opérationnelle.
        statuses.append(status)
        evidence.append({"line_id": line.get("line_id"), "seconds": seconds,
                         "source_line": (line.get("source") or {}).get("line")})
    aggregate = ("FAIL" if "FAIL" in statuses else
                 "UNKNOWN" if "UNKNOWN" in statuses else "PASS")
    return aggregate, {"scope": scope, "max_allowed_seconds": 600, "lines": evidence}


def _local_user_secrets(ir: dict, complete: bool) -> tuple[str, dict]:
    users = _get(ir, "management", "local_accounts")
    if not isinstance(users, list):
        return "UNKNOWN", {"local_user_count": None}
    if not users:
        return ("NOT_APPLICABLE" if complete else "UNKNOWN"), {"local_user_count": 0}
    kinds = [u.get("credential_type") for u in users if isinstance(u, dict)]
    status = ("FAIL" if "password" in kinds else
              "UNKNOWN" if len(kinds) != len(users) or any(k != "secret" for k in kinds)
              else "PASS")
    return status, {"local_user_count": len(users),
                    "secret_count": kinds.count("secret"), "password_count": kinds.count("password")}


def _ssh_version2(ir: dict, _complete: bool) -> tuple[str, dict]:
    value = _get(ir, "management", "ssh_version")
    # Une version absente dans running-config ne prouve pas la version active.
    if value is None:
        return "UNKNOWN", {"ssh_version": None, "requires_live_confirmation": True}
    return ("PASS" if value == 2 else "FAIL"), {"ssh_version": value}


def _snmp_no_rw(ir: dict, complete: bool) -> tuple[str, dict]:
    communities = _get(ir, "services", "snmp", "communities")
    if not isinstance(communities, list):
        return "UNKNOWN", {"community_count": None}
    if not communities:
        return ("NOT_APPLICABLE" if complete else "UNKNOWN"), {"community_count": 0}
    values = [str(c.get("access") or "unknown").lower() for c in communities if isinstance(c, dict)]
    status = ("FAIL" if "rw" in values else
              "UNKNOWN" if len(values) != len(communities) or any(v != "ro" for v in values)
              else "PASS")
    return status, {"community_count": len(communities), "rw_count": values.count("rw"),
                    "unknown_access_count": sum(v not in {"ro", "rw"} for v in values)}


def _snmp_priv(ir: dict, complete: bool) -> tuple[str, dict]:
    groups = _get(ir, "services", "snmp", "groups")
    if not isinstance(groups, list):
        return "UNKNOWN", {"snmp_v3_group_count": None}
    v3 = [g for g in groups if isinstance(g, dict) and g.get("version") == "v3"]
    if not v3:
        return ("NOT_APPLICABLE" if complete else "UNKNOWN"), {"snmp_v3_group_count": 0}
    levels = [g.get("security_level") for g in v3]
    status = ("FAIL" if any(v in {"auth", "noauth"} for v in levels) else
              "UNKNOWN" if any(v != "priv" for v in levels) else "PASS")
    return status, {"snmp_v3_group_count": len(v3), "priv_group_count": levels.count("priv")}


def _syslog_buffer(ir: dict, complete: bool) -> tuple[str, dict]:
    buffer = _get(ir, "services", "syslog", "buffered")
    if buffer is None:
        return _missing(complete, {"buffer_size_bytes": None})
    if not isinstance(buffer, dict):
        return "UNKNOWN", {"reason": "buffer_not_structured"}
    size = buffer.get("size_bytes")
    if buffer.get("enabled") is False:
        return "FAIL", {"enabled": False, "buffer_size_bytes": size}
    if buffer.get("enabled") is True and isinstance(size, int) and size > 0:
        return ("PASS" if size >= 64000 else "FAIL"), {
            "enabled": True, "buffer_size_bytes": size,
            "recommended_size_bytes": 64000,
        }
    return "UNKNOWN", {"enabled": buffer.get("enabled"), "buffer_size_bytes": size,
                       "recommended_size_bytes": 64000}


def _syslog_host(ir: dict, complete: bool) -> tuple[str, dict]:
    hosts = _get(ir, "services", "syslog", "targets")
    if not isinstance(hosts, list):
        return "UNKNOWN", {"configured_targets": None}
    if not hosts:
        return _missing(complete, {"configured_targets": 0})
    valid = 0
    for host in hosts:
        try:
            ipaddress.ip_address(str(host.get("address")))
        except (ValueError, AttributeError):
            continue
        valid += 1
    return ("PASS" if valid else "UNKNOWN"), {
        "configured_targets": len(hosts), "ip_address_targets": valid,
    }


def _syslog_informational(ir: dict, complete: bool) -> tuple[str, dict]:
    value = _get(ir, "services", "syslog", "severity")
    if value is None:
        return _missing(complete, {"trap_severity": None})
    return ("PASS" if str(value).lower() in {"informational", "6"} else "FAIL"), {
        "trap_severity": value,
    }


def _ntp_key_count(ir: dict, complete: bool, key: str) -> tuple[str, dict]:
    value = _get(ir, "services", "ntp", key)
    if not isinstance(value, int) or value < 0:
        return "UNKNOWN", {"ir_path": "services.ntp." + key}
    if value:
        return "PASS", {"ir_path": "services.ntp." + key, "count": value}
    return _missing(complete, {"ir_path": "services.ntp." + key, "count": 0})


def _ntp_server_key(ir: dict, complete: bool) -> tuple[str, dict]:
    servers = _get(ir, "services", "ntp", "servers")
    if not isinstance(servers, list):
        return "UNKNOWN", {"ntp_server_count": None}
    if not servers:
        return ("NOT_APPLICABLE" if complete else "UNKNOWN"), {"ntp_server_count": 0}
    keyed = sum(s.get("authentication_key_referenced") is True for s in servers if isinstance(s, dict))
    opaque = sum(bool(s.get("unmodeled_token_count")) for s in servers if isinstance(s, dict))
    ntp = _get(ir, "services", "ntp") or {}
    defined = ntp.get("defined_key_ids")
    trusted = ntp.get("trusted_key_ids")
    references = [str(s.get("authentication_key_id")) for s in servers if isinstance(s, dict)
                  and s.get("authentication_key_id") is not None]
    relationships_known = isinstance(defined, list) and isinstance(trusted, list)
    invalid_references = sum(k not in set(defined) or k not in set(trusted)
                             for k in references) if relationships_known else 0
    if keyed == len(servers) and not opaque and relationships_known and len(references) == len(servers) and not invalid_references:
        status, evidence = "PASS", {"key_reference_consistency_verified": True}
    elif opaque:
        status, evidence = "UNKNOWN", {"reason": "unmodeled_ntp_server_options"}
    elif keyed == len(servers) and not relationships_known:
        status, evidence = "UNKNOWN", {"reason": "ntp_key_identifier_information_unavailable"}
    elif keyed == len(servers) and len(references) != len(servers):
        status, evidence = "UNKNOWN", {"reason": "ntp_key_identifier_unavailable"}
    elif complete:
        status, evidence = "FAIL", {"inferred_absence": True,
                                   "invalid_key_reference_count": invalid_references}
    else:
        status, evidence = "UNKNOWN", {"invalid_key_reference_count": invalid_references}
    evidence.update({"ntp_server_count": len(servers), "keyed_server_count": keyed})
    return status, evidence


def _ntp_servers(ir: dict, complete: bool) -> tuple[str, dict]:
    servers = _get(ir, "services", "ntp", "servers")
    if not isinstance(servers, list):
        return "UNKNOWN", {"ntp_server_count": None}
    return ("PASS", {"ntp_server_count": len(servers)}) if servers else _missing(
        complete, {"ntp_server_count": 0})


def _ntp_loopback(ir: dict, complete: bool) -> tuple[str, dict]:
    value = _get(ir, "services", "ntp", "source_interface")
    if value is None:
        return _missing(complete, {"source_is_loopback": None})
    valid = isinstance(value, str) and re.fullmatch(r"Loopback\d+", value, re.I) is not None
    return ("PASS" if valid else "FAIL"), {"source_is_loopback": valid}


def _no_tunnels(ir: dict, complete: bool) -> tuple[str, dict]:
    interfaces = ir.get("interfaces")
    if not isinstance(interfaces, list):
        return "UNKNOWN", {"tunnel_count": None}
    tunnels = [i for i in interfaces if isinstance(i, dict) and
               str(i.get("name") or "").lower().startswith("tunnel")]
    if tunnels:
        return "FAIL", {"tunnel_count": len(tunnels), "source_lines": [
            (i.get("source") or {}).get("line") for i in tunnels
        ]}
    if complete:
        return "PASS", {"tunnel_count": 0, "inferred_absence": True}
    return "UNKNOWN", {"tunnel_count": 0}


def _proxy_arp(ir: dict, _complete: bool) -> tuple[str, dict]:
    interfaces = ir.get("interfaces")
    if not isinstance(interfaces, list):
        return "UNKNOWN", {"interface_count": None}
    if not interfaces:
        return "UNKNOWN", {"interface_count": 0}
    explicit_true = sum(i.get("proxy_arp_enabled") is True for i in interfaces if isinstance(i, dict))
    explicit_false = sum(i.get("proxy_arp_enabled") is False for i in interfaces if isinstance(i, dict))
    status = ("FAIL" if explicit_true else "PASS" if explicit_false == len(interfaces) else "UNKNOWN")
    return status, {"interface_count": len(interfaces), "proxy_arp_enabled_count": explicit_true,
                    "proxy_arp_disabled_count": explicit_false,
                    "requires_live_confirmation": status == "UNKNOWN"}


def _bgp_password(ir: dict, complete: bool) -> tuple[str, dict]:
    processes = _get(ir, "routing", "bgp")
    if not isinstance(processes, list):
        return "UNKNOWN", {"bgp_peer_count": None}
    peers = [n for p in processes if isinstance(p, dict)
             for n in p.get("neighbors", []) if isinstance(n, dict) and n.get("kind") == "peer"]
    if not peers:
        return ("NOT_APPLICABLE" if complete else "UNKNOWN"), {"bgp_peer_count": 0}
    protected = sum(p.get("password_configured") is True for p in peers)
    if any(p.get("password_in_af_unverified") for p in peers):
        return "UNKNOWN", {"bgp_peer_count": len(peers),
                           "protected_peer_count": protected,
                           "reason": "password_command_in_unverified_address_family"}
    if protected == len(peers):
        return "PASS", {"bgp_peer_count": len(peers), "protected_peer_count": protected}
    return _missing(complete, {"bgp_peer_count": len(peers), "protected_peer_count": protected})


EXTENDED_CHECKS: dict[str, Callable[[dict, bool], tuple[str, dict]]] = {
    "aaa_new_model": lambda ir, complete: _bool(ir, complete, "management", "aaa_new_model_enabled"),
    "console_exec_timeout": lambda ir, complete: _line_timeout(ir, complete, "con "),
    "vty_exec_timeout": lambda ir, complete: _line_timeout(ir, complete, "vty "),
    "login_banner": lambda ir, complete: _banner(ir, complete, "login"),
    "motd_banner": lambda ir, complete: _banner(ir, complete, "motd"),
    "local_user_secrets": _local_user_secrets,
    "ssh_version2": _ssh_version2,
    "snmp_no_rw": _snmp_no_rw,
    "snmp_v3_priv": _snmp_priv,
    "syslog_buffer": _syslog_buffer,
    "syslog_host": _syslog_host,
    "syslog_informational": _syslog_informational,
    "ntp_auth_keys": lambda ir, complete: _ntp_key_count(ir, complete, "authentication_key_count"),
    "ntp_trusted_keys": lambda ir, complete: _ntp_key_count(ir, complete, "trusted_key_count"),
    "ntp_server_keys": _ntp_server_key,
    "ntp_servers": _ntp_servers,
    "ntp_loopback_source": _ntp_loopback,
    "no_tunnel_interfaces": _no_tunnels,
    "proxy_arp_disabled": _proxy_arp,
    "bgp_neighbor_password": _bgp_password,
}
