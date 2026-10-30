"""Pont Flask vers les normaliseurs Juniper IR v2 existants.

La configuration brute n'est utilisée que pendant la requête : le moteur
Junos externe travaille sur un fichier temporaire automatiquement supprimé.
Aucune valeur CLI brute n'est incluse dans les exports ou les réponses HTTP.
"""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any


def _findings(source_kind: str, combined_unmodeled: int, unmodeled_v1: int,
              unmodeled_v2: int) -> list[dict[str, Any]]:
    rows = [{
        "code": "JUNOS_STATIC_ONLY", "level": "info", "title": "Interprétation statique uniquement",
        "observation": "Les directives sont relevées dans un fichier ; aucune session ou politique effective n'est vérifiée.",
        "advice": "Comparer les données normalisées à la plateforme et au contexte d'exploitation.",
        "source_line": None,
    }]
    if combined_unmodeled:
        rows.append({
            "code": "JUNOS_COVERAGE_PARTIAL", "level": "info", "title": "Couverture IR partielle",
            "observation": (f"{combined_unmodeled} feuilles restent non modélisées après union des "
                            f"adaptateurs ; v1 seule : {unmodeled_v1}, extension v2 seule : "
                            f"{unmodeled_v2}. Ces compteurs ne sont pas additionnables."),
            "advice": "Examiner les sections non modélisées avant tout audit de conformité.",
            "source_line": None,
        })
    if source_kind == ".md":
        rows.append({
            "code": "JUNOS_DOC_EXCERPT", "level": "info", "title": "Document d'exemple",
            "observation": "Entrée Markdown contenant des commandes set ; l'exhaustivité n'est pas attestée.",
            "advice": "Pour une validation réelle, utiliser une sauvegarde de configuration du constructeur.",
            "source_line": None,
        })
    return rows


def analyze_juniper(content: str, filename: str, digest: str) -> tuple[dict, dict, dict, dict]:
    """Retourne (résultat UI, IR v2, revue prudente, aperçu de parsing sûr)."""
    from jsonschema import Draft202012Validator
    from normalizers.junos_tree_loader import load_junos_tree
    from normalizers.policy_ir_v2 import normalize_juniper_junos_v2
    from webapp.juniper_parsed_preview import safe_junos_parsed_preview

    # Normaliseurs existants basés sur Path. La persistance temporaire n'est
    # ni une archive ni un cache : répertoire privé supprimé à la fin du bloc.
    with TemporaryDirectory(prefix="netaudit-junos-") as directory:
        temporary_path = Path(directory) / ("input.md" if Path(filename).suffix.lower() == ".md" else "input.cfg")
        temporary_path.write_text(content, encoding="utf-8")
        ir = normalize_juniper_junos_v2(temporary_path)
        parsed = load_junos_tree(temporary_path)

    schema_path = Path(__file__).resolve().parent.parent / "schemas/network_device_ir_v2.schema.json"
    import json
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    issues = list(Draft202012Validator(schema).iter_errors(ir))
    if issues:
        raise ValueError("IR Juniper non conforme au schéma v2")

    # Le nom temporaire n'apparaît pas dans les livrables.
    ir["source"]["file"] = filename
    ir["source"]["sha256"] = digest
    counts = ir["diagnostics"].get("source_only_counts") or {}
    v1_missing = int(counts.get("unmodeled_leaves") or 0)
    missing_by_section = counts.get("junos_v2_feature_unmodeled_by_section") or {}
    recognized_by_section = counts.get("junos_v2_feature_recognized_by_section") or {}
    v2_missing = sum(int(x) for x in missing_by_section.values())
    combined_missing = int(counts.get("combined_unmodeled_leaves", v1_missing))

    routed = ir.get("routing") or {}
    details = ir.get("junos_details") or {}
    protos = details.get("protocols") or {}
    interfaces = ir.get("interfaces") or []
    full_interfaces = details.get("interfaces") or []
    names = sorted({entry.get("name") for entry in interfaces + full_interfaces if entry.get("name")})
    ip_by_name: dict[str, list[str]] = {}
    for entry in interfaces:
        ip_by_name.setdefault(entry.get("name", ""), []).extend(
            a.get("cidr") or a.get("address") for a in entry.get("ipv4_addresses") or []
            if a.get("cidr") or a.get("address")
        )
    for entry in full_interfaces:
        for family in (entry.get("families") or {}).values():
            if isinstance(family, dict):
                ip_by_name.setdefault(entry["name"], []).extend(family.get("addresses") or [])
    interface_preview = [
        {"name": name, "addresses": list(dict.fromkeys(ip_by_name.get(name, []))),
         "admin_state": "Non déterminé depuis la configuration"}
        for name in names
    ]

    # Parité de restitution avec Cisco : cet export détaillé est extrait
    # exclusivement de l'AST tiers, et non reconstruit à partir de l'IR.
    preview = safe_junos_parsed_preview(parsed, filename)

    findings = _findings(Path(filename).suffix.lower(), combined_missing, v1_missing, v2_missing)
    finding_totals = {"warning": 0, "success": 0, "info": len(findings)}
    result_counts = {
        "interfaces": len(names),
        "ospf": max(len(routed.get("ospf") or []), len((protos.get("ospf") or {}).get("areas") or [])),
        "bgp": max(len(routed.get("bgp") or []), len((protos.get("bgp") or {}).get("groups") or [])),
        "acl": len((details.get("auxiliary") or {}).get("security", {}).get("policies") or []),
        "unparsed_global": combined_missing,
    }
    hostname = ir.get("device", {}).get("hostname") or "Juniper (nom non attesté)"
    result = {
        "file": filename, "vendor": "juniper_junos", "hostname": hostname,
        "format": "junos_" + parsed.format, "format_confidence": "syntax_only",
        "status": "a_verifier", "counts": result_counts, "interfaces": interface_preview,
        "findings": findings, "finding_totals": finding_totals,
        "coverage": {
            "global_unknown": 0, "nested_unknown": combined_missing, "platform_unknown": v1_missing,
            "platform_modeled": sum(recognized_by_section.values()),
            "platform_scope_limited": 0, "formatting_recoveries": 0,
            "nested_categories": missing_by_section,
            "v1_unmodeled": v1_missing, "v2_unmodeled": v2_missing,
            "combined_total": int(counts.get("combined_total_leaves", 0)),
            "combined_modeled": int(counts.get("combined_modeled_leaves", 0)),
            "combined_unmodeled": combined_missing,
            "combined_unmodeled_by_section": counts.get("combined_unmodeled_by_section") or {},
            "v2_recognized_by_section": recognized_by_section,
            "v2_unmodeled_by_section": missing_by_section,
        },
    }
    review = {
        "hostname": hostname, "file": filename, "vendor": "juniper_junos",
        "counts": result_counts, "interfaces": interface_preview,
        "findings": findings, "finding_totals": finding_totals,
    }
    return result, ir, review, preview
