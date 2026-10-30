#!/usr/bin/env python3
"""Rapport HTML de validation statique pour les extractions Cisco IOS V6.

Usage (depuis la racine de network-config-audit) :
    PYTHONPATH=parsers python3 scripts/report_validation.py data/validation/R-AUDIT-EDGE-01.cfg --output reports/validation.html
    PYTHONPATH=parsers python3 scripts/report_validation.py data/parsed_v6 --output reports/flotte.html

Les constats sont des INDICATEURS de configuration, et non une preuve d'état
opérationnel, une certification de conformité ou une supervision temps réel.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from html import escape
import ipaddress
import json
from pathlib import Path
import sys
from typing import Any


SUFFIXES = {".cfg", ".txt", ".json"}
STATUS_TEXT = {"warning": "À VÉRIFIER", "success": "OK", "info": "INFORMATION"}


def parse_source(path: Path) -> dict[str, Any]:
    if path.suffix.lower() == ".json":
        content = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(content, dict) or "interfaces" not in content:
            raise ValueError(f"JSON non reconnu comme extraction IOS V6 : {path}")
        return content
    try:
        from cisco_parser import parse_cisco_ios
    except ImportError:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "parsers"))
        from cisco_parser import parse_cisco_ios
    return parse_cisco_ios(path.read_text(encoding="utf-8"))


def _line(item: dict[str, Any]) -> int | None:
    value = item.get("source_line", item.get("line"))
    return value if isinstance(value, int) and value > 0 else None


def _finding(
    code: str,
    level: str,
    title: str,
    observation: str,
    advice: str,
    line: int | None = None,
) -> dict[str, Any]:
    return {
        "code": code, "level": level, "title": title,
        "observation": observation, "advice": advice, "source_line": line,
    }


def _count_hsrp(interfaces: list[dict[str, Any]]) -> int:
    return sum(len(i.get("hsrp_groups", [])) for i in interfaces)


def analyze_device(parsed: dict[str, Any], source: str) -> dict[str, Any]:
    """Construire une restitution SÛRE : aucune ligne brute ni secret exporté."""
    interfaces = parsed.get("interfaces", [])
    ospf = parsed.get("ospf_processes", [])
    bgp = parsed.get("bgp_processes", [])
    snmp = parsed.get("snmp", {}) or {}
    syslog = parsed.get("syslog", {}) or {}
    globals_ = parsed.get("global_settings", {}) or {}
    acls = parsed.get("access_lists", [])
    findings: list[dict[str, Any]] = []

    def add(code: str, level: str, title: str, detail: str, advice: str, line: int | None = None) -> None:
        findings.append(_finding(code, level, title, detail, advice, line))

    hostname = parsed.get("hostname")
    if hostname:
        add("HOSTNAME", "success", "Identification de l'équipement", "Hostname configuré et extrait.", "Aucune action.")
    else:
        add("HOSTNAME", "warning", "Hostname absent", "Aucun hostname n'a été identifié.", "Vérifier la source et déclarer un hostname explicite.")

    seen: set[str] = set()
    invalid_addresses = 0
    for interface in interfaces:
        name = str(interface.get("name", "?"))
        source_line = _line(interface)
        if name in seen:
            add("INTERFACE_DUPLICATE", "warning", "Définition d'interface répétée", f"Interface {name} déclarée plusieurs fois.", "Vérifier la configuration effective et la fusion des blocs.", source_line)
        seen.add(name)
        for ip in interface.get("ipv4_addresses", []):
            try:
                ipaddress.IPv4Interface(f"{ip['address']}/{ip['mask']}")
            except (ValueError, KeyError, TypeError):
                invalid_addresses += 1
                add("IPV4_INVALID", "warning", "Adresse IPv4 ou masque invalide", f"Adresse non valide sur l'interface {name}.", "Corriger l'adresse ou le masque de cette interface.", source_line)
    if invalid_addresses == 0 and interfaces:
        add("IPV4_VALID", "success", "Format des adresses IPv4", "Les adresses IPv4 extraites ont une syntaxe valide.", "Vérifier séparément le plan d'adressage et les éventuels conflits.")

    unknown = parsed.get("unparsed_lines", [])
    if unknown:
        add("UNPARSED", "warning", "Directives non classées", f"{len(unknown)} ligne(s) globale(s) non interprétée(s).", "Examiner les lignes originales, enrichir le parseur ou justifier explicitement leur exclusion.")
    else:
        add("UNPARSED", "success", "Classification des directives globales", "Aucune ligne globale non classée dans ce fichier.", "Attention : des directives reconnues peuvent rester stockées sans interprétation sémantique.")
    platform = parsed.get("platform_commands", [])
    if platform:
        add("PLATFORM_RAW", "info", "Directives de plateforme brutes", f"{len(platform)} directive(s) conservée(s) sans interprétation complète.", "Ne pas déduire leur conformité de leur seule classification.")

    vty = [x for x in parsed.get("lines", []) if "vty" in str(x.get("name", x.get("identifier", ""))).lower()]
    if vty:
        for item in vty:
            input_ = [str(x).lower() for x in (item.get("transport_input") or [])]
            if "telnet" in input_ or "all" in input_:
                add("TELNET", "warning", "Accès distant Telnet autorisé", "Un bloc VTY permet Telnet ou tous les transports.", "Restreindre l'accès distant à SSH et contrôler les ACL VTY.", _line(item))
            elif input_ == ["ssh"]:
                add("VTY_SSH", "success", "Transport VTY restreint à SSH", "La directive VTY limite explicitement le transport entrant à SSH.", "Vérifier aussi AAA, authentification et ACL de gestion.", _line(item))
            elif not input_:
                add("VTY_UNKNOWN", "info", "Transport VTY non explicite", "Aucune directive de transport entrant n'a été extraite.", "Vérifier les valeurs par défaut de la plateforme et l'accès distant.", _line(item))
    if globals_.get("http_server_enabled") is True:
        add("HTTP_SERVER", "warning", "Serveur HTTP activé", "Le serveur HTTP non chiffré est explicitement activé.", "Désactiver HTTP si inutile ; sinon privilégier une administration chiffrée et filtrée.")
    elif globals_.get("http_server_enabled") is False:
        add("HTTP_SERVER", "success", "Serveur HTTP désactivé", "La directive « no ip http server » est présente.", "Aucune action pour ce point ; vérifier séparément HTTPS.")
    else:
        add("HTTP_UNKNOWN", "info", "État HTTP non déterminé", "Le fichier ne permet pas de conclure sur l'état du serveur HTTP.", "Vérifier la configuration effective et les défauts de version.")

    communities = snmp.get("communities", [])
    if communities:
        for community in communities:
            access = str(community.get("access") or "").upper()
            if access == "RW":
                add("SNMP_RW", "warning", "Communauté SNMP en écriture", "Une communauté SNMP RW est configurée (valeur volontairement masquée).", "Préférer SNMPv3 avec authentification/chiffrement, limiter les sources et les droits.", _line(community))
            elif access == "RO":
                add("SNMP_RO", "info", "Communauté SNMP RO", "Une communauté SNMP en lecture seule est configurée (valeur masquée).", "Planifier SNMPv3 et vérifier les ACL de restriction.", _line(community))
            else:
                add("SNMP_ACCESS", "info", "Communauté SNMP : accès non précisé", "Type d'accès SNMP non identifiable dans l'extraction (secret masqué).", "Examiner les droits effectifs et migrer si possible vers SNMPv3.", _line(community))
    for host in snmp.get("hosts", []):
        if str(host.get("version") or "").lower() in {"1", "2", "2c"}:
            add("SNMP_LEGACY", "warning", "Destination SNMPv1/v2c", "Une destination SNMP utilise une version sans chiffrement natif.", "Préférer SNMPv3 authPriv, lorsque l'environnement le permet.", _line(host))

    if syslog.get("hosts"):
        add("SYSLOG", "success", "Collecte Syslog déclarée", f"{len(syslog['hosts'])} destination(s) Syslog sont configurées.", "Vérifier réellement l'acheminement, l'horodatage et la conservation des journaux.")
    else:
        add("SYSLOG", "info", "Aucune destination Syslog détectée", "La configuration fournie ne contient pas d'hôte Syslog reconnu.", "Vérifier les exigences de centralisation ; les journaux locaux ne sont pas évalués.")

    for user in parsed.get("local_users", []):
        if user.get("credential_configured") is False:
            add("LOCAL_USER", "warning", "Compte local sans secret extrait", "Un compte local ne possède pas de secret reconnu par le parseur (identité masquée).", "Examiner l'authentification locale et AAA.", _line(user))

    for acl in acls:
        for entry in acl.get("entries", []):
            src = entry.get("source") or {}
            dst = entry.get("destination") or {}
            if (entry.get("action") == "permit" and entry.get("protocol") == "ip"
                    and src.get("kind") == "any" and dst.get("kind") == "any"):
                add("ACL_PERMIT_ANY", "warning", "Règle ACL IPv4 très permissive", "Une ACE autorise « permit ip any any ».", "Examiner l'ordre des ACE, le sens et le point d'application avant de statuer.", _line(entry))

    route_map_names = {x.get("name") for x in parsed.get("route_maps", [])}
    for process in bgp:
        for neighbor in process.get("neighbors", []):
            if neighbor.get("is_peer_group"):
                continue
            if not neighbor.get("effective_remote_as", neighbor.get("remote_as")):
                add("BGP_REMOTE_AS", "warning", "Voisin BGP sans AS distant résolu", "Un voisin BGP n'a pas de remote-as explicite ou hérité dans l'extraction.", "Contrôler la déclaration du voisin et son peer-group.", _line(neighbor))
            for policy in neighbor.get("route_maps", []):
                if policy.get("name") not in route_map_names:
                    add("BGP_POLICY_MISSING", "warning", "Route-map BGP référencée introuvable", "Une route-map référencée par un voisin BGP n'a pas de définition extraite.", "Contrôler le nom, le fichier complet et les dépendances de politique.", _line(policy))

    nat_rules = parsed.get("nat_rules", [])
    if nat_rules:
        roles = {i.get("nat_role") for i in interfaces}
        if not {"inside", "outside"}.issubset(roles):
            add("NAT_ROLES", "warning", "Rôles NAT incomplets", "Au moins une règle NAT existe, mais les interfaces inside/outside ne sont pas toutes identifiées.", "Vérifier le placement des interfaces et le chemin du trafic.")
        else:
            add("NAT_ROLES", "success", "Interfaces NAT déclarées", "Les rôles NAT inside et outside sont présents.", "Une simulation ou un test réseau reste nécessaire pour valider la traduction.")

    for interface in interfaces:
        vrf = interface.get("vrf_forwarding")
        if vrf and vrf not in {v.get("name") for v in parsed.get("vrfs", [])}:
            add("VRF_UNDEFINED", "warning", "VRF d'interface sans définition extraite", "Une interface référence une VRF absente de l'extraction.", "Vérifier la définition de VRF et la complétude de la configuration.", _line(interface))

    counts = {
        "interfaces": len(interfaces), "ospf": len(ospf), "bgp": len(bgp),
        "static_routes": len(parsed.get("static_routes", [])),
        "acl": len(acls), "prefix_lists": len(parsed.get("prefix_lists", [])),
        "route_maps": len(parsed.get("route_maps", [])),
        "vrf": len(parsed.get("vrfs", [])), "nat": len(nat_rules),
        "dhcp_pools": len(parsed.get("dhcp_pools", [])),
        "hsrp": _count_hsrp(interfaces), "snmp_communities": len(communities),
        "syslog_hosts": len(syslog.get("hosts", [])),
        "unparsed_global": len(unknown), "raw_platform": len(platform),
    }

    # Seulement des informations non sensibles, explicitement choisies.
    interface_rows = [{
        "name": str(i.get("name", "?")),
        "addresses": [f"{x.get('address', '?')}/{x.get('mask', '?')}" for x in i.get("ipv4_addresses", [])],
        "admin_state": ("Arrêt administratif" if i.get("administrative_command") == "shutdown"
                        else "Commande no shutdown" if i.get("administrative_command") == "no shutdown"
                        else "Non explicité"),
        "vrf": str(i.get("vrf_forwarding") or "—"),
        "line": _line(i),
    } for i in interfaces]
    return {
        "source": source, "hostname": str(hostname or "Non identifié"),
        "vendor": str(parsed.get("vendor") or "inconnu"),
        "ios_version": str(globals_.get("ios_version") or "non spécifiée"),
        "counts": counts, "findings": findings, "interfaces": interface_rows,
        "finding_totals": dict(Counter(f["level"] for f in findings)),
    }


def _esc(value: Any) -> str:
    return escape(str(value), quote=True)


def _display_address(value: str) -> str:
    """Convertir un couple IP/masque en CIDR si le format est valide."""
    try:
        return str(ipaddress.IPv4Interface(value))
    except (ValueError, TypeError):
        return "Adresse invalide"


def render_html(report: dict[str, Any]) -> str:
    devices = report["devices"]
    fleet_counts = report["totals"]
    content: list[str] = []
    for index, device in enumerate(devices, 1):
        counts = device["counts"]
        status = device["finding_totals"]
        rows = "".join(
            f'<tr><td><span class="tag {f["level"]}">{STATUS_TEXT[f["level"]]}</span></td>'
            f'<td><strong>{_esc(f["title"])}</strong><small>{_esc(f["observation"])}</small></td>'
            f'<td>{_esc(f["advice"])}</td>'
            f'<td>{f["source_line"] if f["source_line"] else "—"}</td></tr>'
            for f in device["findings"]
        )
        int_rows = "".join(
            f'<tr><td>{_esc(it["name"])}</td><td>{_esc(", ".join(_display_address(x) for x in it["addresses"]) or "—")}</td>'
            f'<td>{_esc(it["admin_state"])}</td><td>{_esc(it["vrf"])}</td>'
            f'<td>{it["line"] if it["line"] else "—"}</td></tr>'
            for it in device["interfaces"]
        ) or '<tr><td colspan="5">Aucune interface extraite</td></tr>'
        chips = "".join(f'<span class="chip">{_esc(label)} <b>{counts[key]}</b></span>' for key, label in (
            ("interfaces", "Interfaces"), ("ospf", "OSPF"), ("bgp", "BGP"),
            ("static_routes", "Routes"), ("acl", "ACL"), ("vrf", "VRF"),
            ("nat", "NAT"), ("hsrp", "HSRP"), ("syslog_hosts", "Syslog"),
        ))
        content.append(f"""
        <section class="device" id="equipement-{index}">
          <div class="device-head"><div><h2>{_esc(device['hostname'])}</h2>
          <p>{_esc(device['source'])} · IOS {_esc(device['ios_version'])}</p></div>
          <div class="right"><span class="tag warning">{status.get('warning', 0)} point(s) à vérifier</span>
          <span class="tag success">{status.get('success', 0)} OK</span></div></div>
          <div class="chips">{chips}</div>
          <h3>Contrôles de configuration</h3>
          <div class="table-wrap"><table><thead><tr><th>Statut</th><th>Observation</th><th>Action conseillée</th><th>Ligne</th></tr></thead>
          <tbody>{rows}</tbody></table></div>
          <h3>Interfaces extraites</h3>
          <div class="table-wrap"><table><thead><tr><th>Interface</th><th>IPv4</th><th>Commande administrative</th><th>VRF</th><th>Ligne</th></tr></thead>
          <tbody>{int_rows}</tbody></table></div>
          <p class="muted">Directives globales non classées : <b>{counts['unparsed_global']}</b> · Directives de plateforme gardées brutes : <b>{counts['raw_platform']}</b>.</p>
        </section>""")

    menu = "".join(f'<a href="#equipement-{i}">{_esc(d["hostname"])} <small>{_esc(d["source"])}</small></a>' for i, d in enumerate(devices, 1))
    return f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Validation statique — Cisco IOS</title><style>
*{{box-sizing:border-box}}body{{margin:0;background:#f3f6fb;color:#172b4d;font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}}
header{{background:#102b53;color:white;padding:36px max(20px,calc((100vw - 1180px)/2))}}
header p{{color:#d8e5f9;margin:8px 0 0}}h1{{margin:0;font-size:29px;letter-spacing:-.4px}}h2{{margin:0;font-size:23px}}h3{{margin:24px 0 9px;font-size:16px}}
main{{max-width:1180px;padding:24px;margin:0 auto}}.notice{{border-left:4px solid #e5a42e;background:#fff9e9;border-radius:7px;padding:14px 18px;margin:0 0 21px}}
.metrics{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}}.metric{{background:#fff;border-radius:10px;padding:15px 18px;border:1px solid #e2e8f3}}
.metric b{{font-size:30px;display:block}}.metric span{{font-size:13px;color:#5c6d82}}.index{{display:flex;gap:8px;flex-wrap:wrap;margin:20px 0}}
.index a{{background:#fff;border:1px solid #dce5f1;border-radius:8px;padding:8px 12px;text-decoration:none;color:#1553a5;font-weight:600}}
.index small{{display:block;color:#69788d;font-size:10px;font-weight:400;max-width:235px;overflow-wrap:anywhere}}
.device{{background:white;border:1px solid #dce5f1;box-shadow:0 2px 9px #21385c09;border-radius:12px;padding:22px;margin-bottom:20px;break-inside:avoid}}
.device-head{{display:flex;justify-content:space-between;gap:15px;align-items:start}}.device-head p{{margin:4px 0 0;color:#64748b;overflow-wrap:anywhere}}
.right{{display:flex;gap:7px;align-items:center;flex-wrap:wrap;justify-content:flex-end}}.tag{{display:inline-block;white-space:nowrap;padding:4px 8px;font-size:11px;font-weight:750;border-radius:99px}}
.tag.success{{color:#16603e;background:#dcfce7}}.tag.warning{{color:#85320f;background:#ffedd5}}.tag.info{{color:#174b95;background:#e0edff}}
.chips{{display:flex;gap:7px;flex-wrap:wrap;margin-top:15px}}.chip{{border:1px solid #dfe7f1;border-radius:20px;padding:4px 10px;font-size:12px;background:#f8fafe}}
.chip b{{margin-left:5px;color:#124b89}}.table-wrap{{overflow-x:auto}}table{{border-collapse:collapse;width:100%;font-size:13px;text-align:left}}
th{{background:#edf3fc;color:#243d62}}td,th{{padding:10px 12px;vertical-align:top;border-bottom:1px solid #e9edf4}}td small{{display:block;font-size:12px;color:#54667e;margin-top:3px}}
td:first-child{{white-space:nowrap}}tr:last-child td{{border-bottom:0}}.muted{{color:#6a7889;font-size:12px}}footer{{color:#64748b;text-align:center;padding:15px 20px 32px;font-size:12px}}
@media(max-width:700px){{.metrics{{grid-template-columns:repeat(2,1fr)}}.device-head{{display:block}}.right{{justify-content:flex-start;margin-top:10px}}.device{{padding:14px}}}}
@media print{{body{{background:white}}header{{background:white;color:#102b53;padding:12px 0}}header p{{color:#44546a}}main{{padding:10px 0}}.device{{box-shadow:none;break-inside:auto}}.index{{display:none}}.table-wrap{{overflow:visible}}table{{font-size:10px}}td,th{{padding:6px}}}}
</style></head><body>
<header><h1>Rapport de validation des configurations Cisco IOS</h1><p>Analyse statique et aide à l'interprétation pour l'administration réseau · {_esc(report['generated_at'])}</p></header>
<main><div class="notice"><strong>Portée du rapport :</strong> contrôle ciblé des paramètres reconnus dans les fichiers. Les statuts « OK »
confirment uniquement une <strong>condition de configuration extraite</strong>, pas la connectivité, les sessions OSPF/BGP, l'efficacité des ACL, le fonctionnement réel du NAT ou la conformité globale.
Un nombre nul de lignes non classées <strong>ne signifie pas</strong> une couverture sémantique à 100 %.</div>
<div class="metrics"><div class="metric"><b>{fleet_counts['devices']}</b><span>Équipements / fichiers</span></div>
<div class="metric"><b>{fleet_counts['warnings']}</b><span>Points à vérifier</span></div>
<div class="metric"><b>{fleet_counts['successes']}</b><span>Contrôles OK</span></div>
<div class="metric"><b>{fleet_counts['unparsed_global']}</b><span>Lignes globales non classées</span></div></div>
<nav class="index" aria-label="Équipements analysés">{menu}</nav>
{''.join(content)}
</main><footer>SUP'COM · Projet 6NLG — rapport généré automatiquement, sans données d'authentification ni commandes brutes.</footer></body></html>
"""


def build_report(sources: list[Path], root: Path | None = None) -> dict[str, Any]:
    devices = []
    for source in sources:
        parsed = parse_source(source)
        relative = str(source.relative_to(root)) if root else source.name
        devices.append(analyze_device(parsed, relative))
    return {
        "report_schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC"),
        "disclaimer": "Validation statique ciblée, sans vérification opérationnelle ni audit de conformité exhaustif.",
        "totals": {
            "devices": len(devices),
            "warnings": sum(d["finding_totals"].get("warning", 0) for d in devices),
            "successes": sum(d["finding_totals"].get("success", 0) for d in devices),
            "informations": sum(d["finding_totals"].get("info", 0) for d in devices),
            "unparsed_global": sum(d["counts"]["unparsed_global"] for d in devices),
        },
        "devices": devices,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Rapport HTML de validation statique des configurations Cisco IOS V6.")
    parser.add_argument("source", type=Path, help="Fichier .cfg/.txt/.json ou répertoire contenant ces fichiers")
    parser.add_argument("--output", type=Path, required=True, help="Chemin du rapport HTML")
    parser.add_argument("--json-summary", type=Path, help="Résumé JSON expurgé des secrets (optionnel)")
    args = parser.parse_args(argv)

    if not args.source.exists():
        parser.error(f"Source introuvable : {args.source}")
    root = args.source if args.source.is_dir() else None
    if root:
        files = sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in SUFFIXES)
    else:
        files = [args.source] if args.source.suffix.lower() in SUFFIXES else []
    if not files:
        parser.error("Aucun fichier de configuration/JSON à analyser (.cfg/.txt/.json).")

    try:
        report = build_report(files, root)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render_html(report), encoding="utf-8")
    if args.json_summary:
        args.json_summary.parent.mkdir(parents=True, exist_ok=True)
        args.json_summary.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    total = report["totals"]
    print(f"Rapport : {args.output}")
    print(f"Équipements : {total['devices']} | À vérifier : {total['warnings']} | OK : {total['successes']} | Informations : {total['informations']}")
    print(f"Lignes globales non classées : {total['unparsed_global']}")
    if args.json_summary:
        print(f"Résumé JSON sans secrets : {args.json_summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
