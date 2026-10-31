"""Presentation-only summary of the mapped CIS IOS 15 lab controls.

This module deliberately does not evaluate compliance or reinterpret the IR.
All verdicts come exclusively from ``audit_cis_ios15``.
"""

from __future__ import annotations

import json
from collections import Counter
from webapp.cis_explanations import enrich_explanation
from webapp.cis_trace import enhance_trace
from webapp.cis_source_evidence import source_excerpts


DOMAINS = (
    ("1", "Administration et accès", "AAA, sessions VTY, comptes, bannières et SNMP"),
    ("2", "Services et supervision", "SSH, Syslog et synchronisation NTP"),
    ("3", "Réseau et routage", "Durcissement IP, ACL WAN, EIGRP, OSPF et BGP"),
)

STATUS_LABELS = {
    "PASS": "Conforme au contrôle",
    "FAIL": "Écart de configuration",
    "UNKNOWN": "Preuve insuffisante",
    "NOT_APPLICABLE": "Non applicable",
    "NOT_SELECTED": "Hors profil",
    "NOT_EVALUATED": "Non évalué",
}

RISK_BY_CHECK = {
    "aaa_new_model": "HIGH", "aaa_login_default": "HIGH",
    "aaa_enable_default": "HIGH", "aaa_line_console": "HIGH",
    "aaa_line_tty": "HIGH", "aaa_line_vty": "HIGH",
    "console_exec_timeout": "MEDIUM", "vty_exec_timeout": "MEDIUM",
    "exec_banner_present": "LOW", "login_banner": "LOW", "motd_banner": "LOW",
    "syslog_buffer": "MEDIUM", "syslog_host": "HIGH",
    "syslog_informational": "MEDIUM", "syslog_source_present": "MEDIUM",
    "ntp_servers": "MEDIUM", "ntp_loopback_source": "LOW",
    "no_tunnel_interfaces": "MEDIUM",
    "vty_ssh_only": "HIGH", "ssh_version2": "HIGH",
    "enable_secret_present": "HIGH", "local_user_secrets": "HIGH",
    "snmp_no_rw": "HIGH", "snmp_v3_priv": "HIGH",
    "source_routing_disabled": "MEDIUM", "proxy_arp_disabled": "MEDIUM",
    "external_antispoof_acl": "HIGH", "external_inbound_acl": "HIGH",
    "vty_access_class": "HIGH", "vty_restricting_acl": "HIGH",
    "bgp_neighbor_password": "HIGH", "ntp_auth_enabled": "MEDIUM",
    "ntp_auth_keys": "MEDIUM", "ntp_trusted_keys": "MEDIUM",
    "ntp_server_keys": "MEDIUM", "ospf_area_md5": "HIGH",
    "ospf_interface_md5": "HIGH", "eigrp_interface_md5": "HIGH",
    "eigrp_interface_keychain": "HIGH",
}

# Human-reviewable lab interpretations of the mapped checks. The precise CIS
# reference and remediation still come from the bundled, reviewed catalogue.
EXPECTED_BY_CHECK = {
    "aaa_new_model": "Activer aaa new-model pour la gestion des authentifications.",
    "vty_ssh_only": "Toutes les lignes VTY doivent autoriser uniquement transport input ssh.",
    "console_exec_timeout": "EXEC console : exec-timeout configure a 10 minutes maximum.",
    "vty_exec_timeout": "EXEC VTY : exec-timeout configure a 10 minutes maximum.",
    "exec_banner_present": "Une banniere banner exec doit etre configuree.",
    "login_banner": "Une banniere banner login doit etre configuree.",
    "motd_banner": "Une banniere banner motd doit etre configuree.",
    "enable_secret_present": "Utiliser enable secret (ne jamais exposer le secret dans le rapport).",
    "local_user_secrets": "Les comptes locaux doivent utiliser username secret, et non password.",
    "snmp_no_rw": "Aucune communaute SNMP avec droit RW non protege.",
    "snmp_v3_priv": "Les groupes SNMPv3 concernes utilisent le niveau priv.",
    "ssh_version2": "Configurer ip ssh version 2.",
    "syslog_buffer": "Activer logging buffered avec une taille adaptee (reference : 64000 octets).",
    "syslog_host": "Declarer au moins un collecteur distant avec logging host.",
    "syslog_informational": "Configurer logging trap informational pour la destination distante.",
    "syslog_source_present": "Definir logging source-interface sur une interface stable.",
    "ntp_auth_enabled": "Activer ntp authenticate.",
    "ntp_auth_keys": "Declarer des cles ntp authentication-key sans exposer les valeurs.",
    "ntp_trusted_keys": "Declarer ntp trusted-key pour les identifiants autorises.",
    "ntp_server_keys": "Associer une cle d'authentification aux serveurs NTP configures.",
    "ntp_servers": "Configurer au moins un serveur ntp server autorise.",
    "ntp_loopback_source": "Utiliser ntp source LoopbackX apres validation de la topologie.",
    "source_routing_disabled": "La commande globale no ip source-route doit etre effective.",
    "proxy_arp_disabled": "Configurer no ip proxy-arp sur les interfaces concernees.",
    "no_tunnel_interfaces": "Aucune interface Tunnel non justifiee dans le perimetre audite.",
    "bgp_neighbor_password": "Les voisins BGP configures ont une authentification.",
    "aaa_login_default": "Declarer aaa authentication login default sans methode none.",
    "aaa_enable_default": "Declarer aaa authentication enable default avec une methode valide.",
    "aaa_line_console": "Associer la console a une liste AAA login existante.",
    "aaa_line_tty": "Associer les lignes TTY presentes a une liste AAA login existante.",
    "aaa_line_vty": "Associer toutes les lignes VTY a une liste AAA login existante.",
    "vty_restricting_acl": "Une ACL VTY limite les sources aux postes d'administration autorises.",
    "vty_access_class": "Appliquer access-class NOM in sur chaque plage VTY.",
    "external_antispoof_acl": "Une ACL WAN entrante refuse les adresses sources privees ou reservees pertinentes avant les permis generaux.",
    "external_inbound_acl": "L'interface WAN designee dispose d'une ACL ip access-group NOM in.",
    "eigrp_interface_keychain": "EIGRP : chaine de cles definie et associee aux interfaces participantes.",
    "eigrp_interface_md5": "EIGRP : ip authentication mode eigrp ... md5 sur les interfaces participantes.",
    "ospf_area_md5": "OSPF : authentification message-digest des zones concernees.",
    "ospf_interface_md5": "OSPF : ip ospf message-digest-key sur les interfaces participantes.",
}


def enrich_cis_report(report: dict, catalogue: dict, ir: dict | None = None,
                      source_text: str | None = None) -> None:
    """Add explicit expected-vs-observed context without changing verdicts."""
    by_id = {rule["id"]: rule for rule in catalogue.get("rules", [])}
    for finding in report["findings"]:
        rule = by_id.get(finding["rule_id"], {})
        # Severity reflects impact, NOT likelihood, and does not change CIS decisions.
        finding["risk_level"] = (RISK_BY_CHECK.get(rule.get("check"), "LOW")
                                 if finding["status"] == "FAIL" else "NOT_ASSESSED")
        finding["benchmark_expected"] = EXPECTED_BY_CHECK.get(rule.get("check"), rule.get("title", "Critere non defini"))
        evidence = finding.get("evidence") or {}
        basis = evidence.get("assessment_basis")
        if evidence.get("reason") == "external_interface_not_designated":
            observation = "Impossible d'identifier l'interface WAN : designation utilisateur manquante."
        elif finding["status"] == "NOT_SELECTED":
            observation = "Controle non selectionne dans le profil demande."
        elif finding["status"] == "NOT_APPLICABLE":
            observation = "Non applicable dans la topologie ou la version declaree."
        elif rule.get("check") == "no_tunnel_interfaces" and finding["status"] == "PASS":
            observation = "Aucune interface Tunnel relevée dans la configuration déclarée complète."
        elif basis == "assumed_absence":
            observation = "Directive requise non observee ; absence deduite de la configuration declaree complete."
        elif finding["status"] == "UNKNOWN":
            observation = "Informations insuffisantes dans la configuration / l'IR pour conclure."
        else:
            # Prefer concrete IR facts (configured version, line ranges, counts)
            # over generic PASS/FAIL messages, without exporting CLI secrets.
            check = rule.get("check")
            if check == "vty_ssh_only" and evidence.get("vty_lines"):
                line_values = [f"{line.get('line_id')}: transport={','.join(line.get('transport_input') or []) or 'absent'}"
                               for line in evidence["vty_lines"]]
                observation = "; ".join(line_values)
            elif check in {"console_exec_timeout", "vty_exec_timeout"} and evidence.get("lines"):
                line_values = [f"{line.get('line_id')}: exec-timeout={line.get('seconds')} s"
                               + (" (temporisation desactivee)" if line.get("seconds") == 0 else "")
                               for line in evidence["lines"]]
                observation = "; ".join(line_values)
            else:
                labels = {
                    "observed": "Valeur IR", "ssh_version": "Version SSH",
                    "buffer_size_bytes": "Tampon Syslog", "recommended_size_bytes": "Référence",
                    "trap_severity": "Niveau Syslog", "source_interface": "Interface source",
                    "community_count": "Communautés", "rw_count": "Communautés RW",
                    "snmp_v3_group_count": "Groupes SNMPv3", "local_user_count": "Comptes locaux",
                    "secret_count": "Comptes secret", "password_count": "Comptes password",
                    "configured_targets": "Cibles Syslog", "ntp_server_count": "Serveurs NTP",
                    "count": "Éléments configurés", "tunnel_count": "Interfaces Tunnel",
                    "proxy_arp_enabled_count": "Proxy ARP actif", "proxy_arp_disabled_count": "Proxy ARP inactif",
                    "insecure_none_method": "Méthode AAA none", "line_count": "Lignes",
                    "verified_count": "Lignes validées", "failed_count": "Lignes non conformes",
                    "vty_line_count": "Plages VTY", "restricted_count": "VTY restreintes",
                    "overly_broad_count": "ACL trop permissives", "inbound_acl_count": "ACL entrantes",
                    "early_broad_permit_count": "Permis généraux prématurés",
                    "required_network_count": "Réseaux à bloquer", "invalid_count": "Interfaces invalides",
                    "area_md5_count": "Zones OSPF MD5", "ospf_area_count": "Zones OSPF",
                    "missing_key_count": "Clés manquantes", "wrong_mode_count": "Modes incorrects",
                    "external_interface_count": "Interfaces WAN", "bgp_peer_count": "Voisins BGP",
                    "configured_authentication_interfaces": "Interfaces avec auth configurée",
                }
                facts = []
                for key, label in labels.items():
                    if key in evidence:
                        value = evidence[key]
                        if isinstance(value, bool):
                            value = "oui" if value else "non"
                        elif value is None:
                            value = "non déclaré"
                        facts.append(f"{label}: {value}")
                observation = "; ".join(facts) if facts else (
                    "Critère satisfait dans l'IR." if finding["status"] == "PASS"
                    else "Configuration observée non conforme au critère contrôlé."
                )
                if basis == "assumed_absence":
                    observation += " ; absence inférée (configuration déclarée complète)"
        # No secret values, raw CLI or untrusted free-text are interpolated here.
        finding["observed_summary"] = observation
        finding["evidence_basis"] = basis or "non_specifiee"
        finding["evidence_structured"] = json.dumps(evidence, ensure_ascii=False, sort_keys=True)
        enrich_explanation(finding, rule.get("check", ""))
        enhance_trace(finding, rule.get("check", ""), ir,
                      external_interfaces=report.get("external_interfaces_designated") or [])
        # A section-start anchor is not proof of the precise directive.
        # Preserve the distinction in HTML and PDF exports.
        anchors = finding.get("source_anchors") or []
        finding["source_evidence_quality"] = (
            "DIRECTIVE_LINE" if any(anchor.get("scope") == "ligne de directive" or
                                    anchor.get("scope") == "ligne de règle ACL"
                                    for anchor in anchors)
            else "SECTION_CONTEXT" if anchors else "NO_SOURCE_ANCHOR"
        )
        finding["source_evidence_note"] = (
            "Repères de source indicatifs ; verdict calculé uniquement à partir de l'IR. "
            "Une absence de repère ne démontre pas l'absence de commande."
        )
        if source_text is not None:
            finding["ios_source_excerpts"] = source_excerpts(rule.get("check", ""), source_text)

    # Report independent evidence quality; do not confuse catalogue coverage
    # with validated source provenance or actual equipment compliance.
    evaluated = [finding for finding in report["findings"]
                 if finding["status"] in {"PASS", "FAIL"}]
    qualities = Counter(finding["source_evidence_quality"] for finding in evaluated)
    unanchored = [finding.get("cis_control_id") for finding in evaluated
                  if finding["source_evidence_quality"] == "NO_SOURCE_ANCHOR"]
    report["evidence_quality"] = {
        "assessed_controls": len(evaluated),
        "directive_line": qualities["DIRECTIVE_LINE"],
        "section_context_only": qualities["SECTION_CONTEXT"],
        "no_source_anchor": qualities["NO_SOURCE_ANCHOR"],
        "controls_needing_source_review": unanchored,
        "note": "Les preuves de section ou l'absence de repère ne prouvent pas une directive."
    }


def build_cis_dashboard(report: dict) -> dict:
    """Group findings and expose explicitly bounded, non-certified metrics."""
    counts = report["counts"]
    assessed = counts["PASS"] + counts["FAIL"]
    selected = report["implemented_rule_count"] - counts["NOT_SELECTED"] - counts["NOT_EVALUATED"]
    groups = []
    for prefix, name, subtitle in DOMAINS:
        controls = [finding for finding in report["findings"]
                    if str(finding.get("cis_control_id") or "").startswith(prefix + ".")]
        groups.append({
            "id": prefix,
            "name": name,
            "subtitle": subtitle,
            "total": len(controls),
            "fail": sum(control["status"] == "FAIL" for control in controls),
            "pass": sum(control["status"] == "PASS" for control in controls),
            "unknown": sum(control["status"] == "UNKNOWN" for control in controls),
            "findings": controls,
        })
    return {
        "assessed": assessed,
        "selected": selected,
        "unresolved": counts["UNKNOWN"] + counts["NOT_EVALUATED"],
        "pass_percent_of_assessed": round(100 * counts["PASS"] / assessed, 1) if assessed else None,
        "status_labels": STATUS_LABELS,
        "groups": groups,
    }
