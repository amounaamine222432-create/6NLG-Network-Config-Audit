"""Vérification statique d'un sous-ensemble de contrôles CIS Cisco IOS 15.

Le catalogue fixe les références et les corrections ; ce module ne lit que des
champs IR explicitement autorisés. Il ne modifie jamais la configuration.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from .ir_inventory import build_ir_inventory
from .cis15_extended_checks import EXTENDED_CHECKS
from .cis15_phase5_checks import CHECKS as PHASE5_CHECKS, CONTEXT_CHECKS


_CHECKS = {
    "vty_ssh_only", "exec_banner_present", "enable_secret_present",
    "syslog_source_present", "ntp_auth_enabled", "source_routing_disabled",
} | set(EXTENDED_CHECKS) | set(PHASE5_CHECKS) | set(CONTEXT_CHECKS)


def _nested(ir: dict[str, Any], *keys: str) -> Any:
    result: Any = ir
    for key in keys:
        if not isinstance(result, dict) or key not in result:
            return None
        result = result[key]
    return result


def _missing(complete_config: bool) -> str:
    return "FAIL" if complete_config else "UNKNOWN"


def _check_vty(ir: dict[str, Any], complete_config: bool) -> tuple[str, dict]:
    lines = _nested(ir, "management", "terminal_lines")
    if not isinstance(lines, list):
        return "UNKNOWN", {"vty_lines": []}
    vty = [line for line in lines if isinstance(line, dict)
           and str(line.get("line_id") or "").lower().startswith("vty ")]
    if not vty:
        return "UNKNOWN", {"vty_lines": []}

    checks = []
    evidence = []
    for line in vty:
        transports = line.get("transport_input")
        tokens = [str(v).lower() for v in transports] if isinstance(transports, list) else []
        if tokens == ["ssh"]:
            checks.append("PASS")
        elif not tokens:
            checks.append(_missing(complete_config))
        else:
            checks.append("FAIL")
        evidence.append({
            "line_id": line.get("line_id"),
            "transport_input": tokens,
            "source_line": (line.get("source") or {}).get("line"),
        })
    status = "FAIL" if "FAIL" in checks else ("UNKNOWN" if "UNKNOWN" in checks else "PASS")
    return status, {"vty_lines": evidence}


def _check_banner(ir: dict[str, Any], complete_config: bool) -> tuple[str, dict]:
    banners = _nested(ir, "management", "banners")
    if not isinstance(banners, list):
        return "UNKNOWN", {"exec_banner_configured": None}
    candidates = [b for b in banners if isinstance(b, dict) and b.get("kind") == "exec"]
    return ("PASS" if candidates else _missing(complete_config)), {
        "exec_banner_configured": bool(candidates),
        "source_lines": [(b.get("source") or {}).get("line") for b in candidates],
    }


def _check_boolean(ir: dict[str, Any], path: tuple[str, ...], expected: bool,
                   complete_config: bool) -> tuple[str, dict]:
    observed = _nested(ir, *path)
    if observed is None:
        status = _missing(complete_config)
    elif type(observed) is not bool:
        status = "UNKNOWN"
    else:
        status = "PASS" if observed is expected else "FAIL"
    return status, {"ir_path": ".".join(path), "observed": observed, "expected": expected}


def _check_syslog_source(ir: dict[str, Any], complete_config: bool) -> tuple[str, dict]:
    observed = _nested(ir, "services", "syslog", "source_interface")
    if isinstance(observed, str) and observed.strip():
        return "PASS", {"source_interface": observed}
    return _missing(complete_config), {"source_interface": None}


def _evaluate_check(check: str, ir: dict[str, Any], complete: bool,
                    context: dict[str, Any] | None = None) -> tuple[str, dict]:
    if check in CONTEXT_CHECKS:
        return CONTEXT_CHECKS[check](ir, complete, context or {})
    if check in PHASE5_CHECKS:
        return PHASE5_CHECKS[check](ir, complete)
    if check in EXTENDED_CHECKS:
        return EXTENDED_CHECKS[check](ir, complete)
    if check == "vty_ssh_only":
        return _check_vty(ir, complete)
    if check == "exec_banner_present":
        return _check_banner(ir, complete)
    if check == "enable_secret_present":
        return _check_boolean(ir, ("management", "enable_secret_configured"), True, complete)
    if check == "syslog_source_present":
        return _check_syslog_source(ir, complete)
    if check == "ntp_auth_enabled":
        return _check_boolean(ir, ("services", "ntp", "authentication_enabled"), True, complete)
    if check == "source_routing_disabled":
        return _check_boolean(ir, ("services", "ip_stack", "source_route_enabled"), False, complete)
    raise ValueError(f"Contrôle interdit : {check}")


def _absence_inferred(check: str, evidence: dict) -> bool:
    """Un FAIL dépend-il seulement de l'hypothèse de complétude ?"""
    if evidence.get("inferred_absence") is True:
        return True
    if check == "vty_ssh_only":
        rows = evidence.get("vty_lines") or []
        return bool(rows) and all(not row.get("transport_input") or
                                  row.get("transport_input") == ["ssh"] for row in rows)
    if check == "exec_banner_present":
        return evidence.get("exec_banner_configured") is False
    if check in {"enable_secret_present", "ntp_auth_enabled", "source_routing_disabled"}:
        return evidence.get("observed") is None
    if check == "syslog_source_present":
        return evidence.get("source_interface") is None
    return False


def _parser_uncertainty(check: str, ir: dict[str, Any]) -> list[str]:
    """Signaler les déclarations susceptibles d'avoir échappé au parsing."""
    diagnostics = ir.get("diagnostics") or {}
    reasons = []
    if diagnostics.get("unparsed_global_count", 0):
        reasons.append("unparsed_global_commands")
    if diagnostics.get("formatting_recovery_count", 0):
        reasons.append("recovered_section_formatting")
    scopes = [str(item.get("section") or "") for item in
              (diagnostics.get("opaque_sections") or []) if isinstance(item, dict)]
    related = {
        "vty_ssh_only": ("line",),
        "console_exec_timeout": ("line",),
        "vty_exec_timeout": ("line",),
        "exec_banner_present": ("banner",),
        "login_banner": ("banner",),
        "motd_banner": ("banner",),
        "enable_secret_present": ("management",),
        "aaa_new_model": ("management",),
        "local_user_secrets": ("management",),
        "ssh_version2": ("management",),
        "syslog_source_present": ("syslog",),
        "syslog_buffer": ("syslog",),
        "syslog_host": ("syslog",),
        "syslog_informational": ("syslog",),
        "snmp_no_rw": ("snmp",),
        "snmp_v3_priv": ("snmp",),
        "ntp_auth_enabled": ("ntp",),
        "ntp_auth_keys": ("ntp",),
        "ntp_trusted_keys": ("ntp",),
        "ntp_server_keys": ("ntp",),
        "ntp_servers": ("ntp",),
        "ntp_loopback_source": ("ntp",),
        "source_routing_disabled": ("ip-stack",),
        "proxy_arp_disabled": ("interface",),
        "no_tunnel_interfaces": ("interface",),
        "bgp_neighbor_password": ("bgp", "bgp-neighbor"),
        "aaa_login_default": ("management",),
        "aaa_enable_default": ("management",),
        "aaa_line_console": ("line", "management"),
        "aaa_line_tty": ("line", "management"),
        "aaa_line_vty": ("line", "management"),
        "vty_restricting_acl": ("line", "acl"),
        "vty_access_class": ("line", "acl"),
        "ospf_area_md5": ("ospf", "interface"),
        "ospf_interface_md5": ("ospf", "interface"),
        "eigrp_interface_keychain": ("eigrp", "interface", "key_chain"),
        "eigrp_interface_md5": ("eigrp", "interface"),
        "external_inbound_acl": ("interface", "acl"),
        "external_antispoof_acl": ("interface", "acl"),
    }[check]
    if any(scope == x or scope.startswith(x + ":") for scope in scopes for x in related):
        reasons.append("opaque_commands_in_related_section")
    return reasons


def audit_cis_ios15(
    ir: dict[str, Any], catalogue: dict[str, Any], *,
    profile: str = "L1", complete_config: bool = False,
    parsed: dict[str, Any] | None = None,
    audit_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Comparer l'IR à un sous-ensemble revu du benchmark, sans certification.

    Sans preuve de complétude, les déclarations manquantes donnent UNKNOWN.
    `complete_config=True` est une affirmation explicite de l'utilisateur.
    """
    if profile not in {"L1", "L2"}:
        raise ValueError("Le profil doit être L1 ou L2")
    benchmark = catalogue.get("benchmark", {})
    if (benchmark.get("family") != "Cisco IOS 15" or
            benchmark.get("version") != "4.1.1"):
        raise ValueError("Catalogue non compatible avec CIS Cisco IOS 15 v4.1.1")

    vendor = _nested(ir, "source", "vendor")
    version = _nested(ir, "device", "platform", "version")
    if vendor != "cisco_ios":
        raise ValueError("Un IR Cisco IOS est requis")

    findings = []
    ids: set[str] = set()
    for rule in catalogue.get("rules", []):
        identifier = rule.get("id")
        check = rule.get("check")
        if not isinstance(identifier, str) or not identifier or identifier in ids:
            raise ValueError("Identifiant de règle invalide ou dupliqué")
        ids.add(identifier)
        if check not in _CHECKS:
            raise ValueError(f"Contrôle non autorisé : {check}")
        if rule.get("review_status") != "mapped_for_lab":
            status, evidence = "NOT_EVALUATED", {}
        elif rule.get("profile") == "L2" and profile == "L1":
            status, evidence = "NOT_SELECTED", {}
        elif version is None or not str(version).strip():
            status, evidence = "UNKNOWN", {"reason": "version_ios_inconnue"}
        elif not str(version).strip().startswith("15."):
            status, evidence = "NOT_APPLICABLE", {"reason": "version_ios_non_15"}
        else:
            status, evidence = _evaluate_check(check, ir, complete_config, audit_context)
            if status == "FAIL" and complete_config and _absence_inferred(check, evidence):
                evidence["assessment_basis"] = "assumed_absence"
                uncertainty = _parser_uncertainty(check, ir)
                if uncertainty:
                    status = "UNKNOWN"
                    evidence["uncertainty_reasons"] = uncertainty
            elif status == "PASS" and evidence.get("inferred_absence") is True:
                evidence["assessment_basis"] = "assumed_absence"
                uncertainty = _parser_uncertainty(check, ir)
                if uncertainty:
                    status = "UNKNOWN"
                    evidence["uncertainty_reasons"] = uncertainty
            else:
                evidence["assessment_basis"] = (
                    "explicit_ir" if status in {"PASS", "FAIL"} else "insufficient_evidence"
                )
        findings.append({
            "rule_id": identifier,
            "cis_control_id": rule.get("control_id"),
            "pdf_page": rule.get("pdf_page"),
            "profile": rule.get("profile"),
            "title": rule.get("title"),
            "status": status,
            "evidence": evidence,
            "remediation": rule.get("remediation") if status == "FAIL" else None,
        })

    counts = Counter(f["status"] for f in findings)
    report = {
        "source_file": _nested(ir, "source", "file"),
        "source_sha256": _nested(ir, "source", "sha256"),
        "hostname": _nested(ir, "device", "hostname"),
        "ios_version": version,
        "benchmark": benchmark,
        "selected_profile": profile,
        "complete_config_assumed": complete_config,
        "external_interfaces_designated": list((audit_context or {}).get("external_interfaces") or []),
        "benchmark_conformance_certified": False,
        "implemented_rule_count": len(findings),
        "counts": {key: counts.get(key, 0) for key in (
            "PASS", "FAIL", "UNKNOWN", "NOT_SELECTED", "NOT_APPLICABLE", "NOT_EVALUATED"
        )},
        "findings": findings,
    }
    if parsed is not None:
        report["parsing_normalization_inventory"] = build_ir_inventory(parsed, ir, catalogue)
    return report
