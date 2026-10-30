#!/usr/bin/env python3
"""Read-only Cisco IOS V6 coverage audit, including nested opaque statements.

This is a *coverage* diagnostic, not a network compliance verdict.  It never
prints or exports raw IOS directives (which could contain credentials).
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
import sys

try:
    from cisco_parser import parse_cisco_ios
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "parsers"))
    from cisco_parser import parse_cisco_ios


def _sum_opaque(parsed: dict) -> dict[str, int]:
    """Count unsupported subcommands; do not expose their original text."""
    result = Counter()

    def add(scope: str, entries: object) -> None:
        if isinstance(entries, list):
            result[scope] += len(entries)

    for iface in parsed.get("interfaces", []):
        add("interface", iface.get("other_commands"))
        for hsrp in iface.get("hsrp_groups", []):
            add("hsrp", hsrp.get("other_commands"))
    for ospf in parsed.get("ospf_processes", []):
        add("ospf", ospf.get("other_commands"))
    for bgp in parsed.get("bgp_processes", []):
        add("bgp", bgp.get("other_commands"))
        for af in bgp.get("address_families", []):
            add("bgp-address-family", af.get("other_commands"))
        for neighbor in bgp.get("neighbors", []):
            # BGP neighbor command strings can contain password values.  Only
            # classify commands that the V6 parser did not normalize.
            for directive in neighbor.get("global_commands", []):
                words = directive.split()
                if (not words or words[0] not in
                        {"peer-group", "remote-as", "update-source", "send-community"}
                        and words != ["route-reflector-client"]
                        and words != ["advertise", "additional-paths", "all"]
                        and not (words[0] == "description" and len(words) >= 2
                                 and neighbor.get("description_configured"))
                        and not (len(words) == 3 and words[0] == "route-map"
                                 and words[2] in {"in", "out"}
                                 and any(policy.get("name") == words[1]
                                         and policy.get("direction") == words[2]
                                         and policy.get("address_family") is None
                                         for policy in neighbor.get("route_maps", [])))):
                    result["bgp-neighbor-unmodeled"] += 1
            for lines in (neighbor.get("address_family_commands") or {}).values():
                for directive in lines:
                    words = directive.split()
                    if (words != ["activate"] and words != ["peer-group"]
                            and words != ["route-reflector-client"]
                            and words != ["advertise", "additional-paths", "all"]
                            and (not words or words[0] not in {"route-map", "send-community"})):
                        result["bgp-neighbor-address-family-unmodeled"] += 1
    for scope, items in (
        ("vrf", parsed.get("vrfs")), ("line", parsed.get("lines")),
        ("vlan", parsed.get("vlans")), ("dhcp-pool", parsed.get("dhcp_pools")),
        ("acl", parsed.get("access_lists")),
    ):
        for item in items or []:
            add(scope, item.get("other_commands"))
    for item in parsed.get("route_maps", []):
        for entry in item.get("entries", []):
            add("route-map-other", entry.get("other_commands"))
    for scope, commands in (
        ("nat", parsed.get("nat_other_commands")),
        ("dhcp", parsed.get("dhcp_other_commands")),
        ("snmp", (parsed.get("snmp") or {}).get("other_commands")),
        ("syslog", (parsed.get("syslog") or {}).get("other_commands")),
    ):
        add(scope, commands)
    return {scope: count for scope, count in sorted(result.items()) if count}


def _dialect_hints(content: str) -> list[str]:
    """Flag suspicious XR-style syntax; never claim formal vendor detection."""
    lines = {line.strip().lower() for line in content.splitlines()}
    hints = []
    if "router static" in lines:
        hints.append("router static (style XR possible)")
    if any(line.startswith("interface mgmteth") for line in lines):
        hints.append("interface MgmtEth (style XR possible)")
    if any(line.startswith("interface preconfigure ") for line in lines):
        hints.append("interface preconfigure (style XR possible)")
    if any(line.startswith("segment-routing") for line in lines):
        hints.append("segment-routing (configuration avancee)")
    if "rsvp" in lines:
        hints.append("rsvp (configuration avancee)")
    if any(line.startswith("mpls traffic-eng") for line in lines):
        hints.append("mpls traffic-eng (configuration avancee)")
    return hints


def _source_format(content: str) -> tuple[str, str, list[str]]:
    """Classify file syntax, not verified device identity.

    IOS and early IOS XE can share version 15.x and the classic CLI.
    Exact OS identity must be confirmed separately with `show version`.
    """
    lines = [line.strip() for line in content.splitlines()[:120]]
    lower = [line.lower() for line in lines]
    if any("ios xr configuration" in line for line in lower):
        return "ios_xr_header_confirmed", "high", ["ios_xr_header"]
    if any(line.startswith(("router static", "interface mgmteth")) for line in lower) or any(
        line.startswith("ipv4 address") for line in lower
    ):
        return "ios_xr_syntax_inferred", "high", ["ios_xr_cli_grammar"]
    version = next((match.group(1) for line in lines
                    if (match := re.fullmatch(r"version\s+(\d+\.\d+(?:\.\d+)?)", line))), None)
    if version and version.startswith("15."):
        return "ios_15_classic_syntax_inferred", "high", ["ios_version_15", "classic_cli_grammar"]
    if version and (version.startswith("16.") or version.startswith("17.")):
        return "ios_xe_version_family_inferred", "medium", ["version_16_or_17"]
    indicators = (
        any(line.startswith("hostname ") for line in lower),
        any(line.startswith("interface ") for line in lower),
        any(line.startswith(("ip address ", "ip route ", "router ospf ",
                             "router bgp ", "switchport ", "ip dhcp pool ")) for line in lower),
    )
    if sum(indicators) >= 2:
        return "ios_like_fragment_inferred", "medium", ["classic_cli_fragment"]
    return "undetermined", "none", []


def audit_text(content: str, *, file: str) -> dict:
    parsed = parse_cisco_ios(content)
    nested = _sum_opaque(parsed)
    g = parsed.get("global_settings") or {}
    platform = parsed.get("platform_commands") or []
    platform_modeled = sum(isinstance(item.get("structured"), dict) for item in platform)
    platform_not_documented = sum(
        item.get("structured", {}).get("documentation_status") == "syntax_only"
        for item in platform if isinstance(item.get("structured"), dict)
    )
    platform_scope_limited = sum(
        item.get("structured", {}).get("documentation_status") == "vendor_documented_platform_specific"
        for item in platform if isinstance(item.get("structured"), dict)
    )
    platform_unmodeled = len(platform) - platform_modeled
    raw_only = {
        "platform_commands": len(platform),
        "platform_modeled": platform_modeled,
        "platform_semantics_unverified": platform_not_documented,
        "platform_documented_scope_limited": platform_scope_limited,
        "platform_unmodeled": platform_unmodeled,
        "service_commands": len(g.get("service_commands") or []),
        "service_timestamps": len(g.get("service_timestamps") or []),
        "system_stanza_commands": sum(len(x.get("commands") or []) for x in parsed.get("system_stanzas", [])),
    }
    global_unknown = len(parsed.get("unparsed_lines", []))
    nested_unknown = sum(nested.values())
    hints = _dialect_hints(content)
    source_format, format_confidence, format_evidence = _source_format(content)
    # A zero in global_unknown never proves full semantic interpretation.
    return {
        "file": file,
        "hostname": parsed.get("hostname"),
        "parser_label": parsed.get("vendor"),
        "source_format": source_format,
        "format_confidence": format_confidence,
        "format_evidence": format_evidence,
        "device_os_identity_verified": False,
        "ios_family_compatible": source_format in {
            "ios_15_classic_syntax_inferred", "ios_xe_version_family_inferred",
            "ios_like_fragment_inferred",
        },
        "formatting_recovery_count": len(parsed.get("formatting_recoveries") or []),
        "ios_xr_or_advanced_syntax_hints": hints,
        "unparsed_global_count": global_unknown,
        "unparsed_global_line_numbers": [u["line"] for u in parsed.get("unparsed_lines", [])],
        "nested_opaque_by_scope": nested,
        "nested_opaque_count": nested_unknown,
        "source_only_counts": raw_only,
        "fully_modeled": False,
        "status": ("incompatible_ios_xr_input" if source_format == "ios_xr_header_confirmed"
                   else "review_dialect_before_normalization" if source_format == "ios_xr_syntax_inferred"
                   else "review_dialect_before_normalization" if hints and global_unknown
                   else "global_or_nested_commands_not_modeled" if global_unknown or nested_unknown
                   else "platform_syntax_not_modeled" if platform_unmodeled
                   else "platform_semantics_pending" if platform_not_documented
                   else "platform_scope_review_pending" if platform_scope_limited
                   else "recovered_unindented_subcommands" if parsed.get("formatting_recoveries")
                   else "dialect_undetermined" if source_format == "undetermined"
                   else "no_global_nested_or_platform_unknowns"),
    }


def run(sources: list[Path]) -> list[dict]:
    outcomes = []
    for source in sources:
        if not source.exists():
            raise FileNotFoundError(f"Chemin introuvable : {source}")
        files = (sorted(p for p in source.rglob("*") if p.is_file() and p.suffix.lower() in {".cfg", ".txt"})
                 if source.is_dir() else [source])
        for p in files:
            item = audit_text(p.read_text(encoding="utf-8-sig"), file=str(p))
            outcomes.append(item)
    return outcomes


def main() -> int:
    cli = argparse.ArgumentParser(description="Auditer la couverture du parseur IOS jusque dans les sous-sections")
    cli.add_argument("sources", type=Path, nargs="+", help="Fichiers .cfg/.txt ou dossiers")
    cli.add_argument("--json-summary", type=Path, help="Résumé JSON sans commandes brutes")
    cli.add_argument("--strict", action="store_true", help="Code retour 2 si commandes globales/imbriquées/plateforme inconnues")
    cli.add_argument("--require-documented-platform", action="store_true",
                     help="Code retour 2 si une directive manque de documentation applicable à la plateforme")
    cli.add_argument("--require-ios-family", action="store_true",
                     help="Code retour 2 si le fichier ressemble à IOS XR ou reste indéterminé")
    cli.add_argument("--require-export-evidence", action="store_true",
                     help="Code retour 2 si aucun export IOS 15.x explicite n'est détecté")
    args = cli.parse_args()
    try:
        items = run(args.sources)
    except (FileNotFoundError, OSError, UnicodeError) as exc:
        cli.error(str(exc))
    for item in items:
        print(f"{item['file']}: globales={item['unparsed_global_count']}, "
              f"sous_sections={item['nested_opaque_count']}, "
              f"plateforme={item['source_only_counts']['platform_commands']}"
              f" (modélisées={item['source_only_counts']['platform_modeled']}, "
              f"sens_à_confirmer={item['source_only_counts']['platform_semantics_unverified']}, "
              f"inconnues={item['source_only_counts']['platform_unmodeled']})"
              f" | format={item['source_format']} ({item['format_confidence']}) | {item['status']}")
        if item["nested_opaque_by_scope"]:
            print("  Sous-sections : " + ", ".join(
                f"{k}={v}" for k, v in item["nested_opaque_by_scope"].items()))
        if item["ios_xr_or_advanced_syntax_hints"]:
            print("  Vérification syntaxe : " + "; ".join(item["ios_xr_or_advanced_syntax_hints"]))
        if item["formatting_recovery_count"]:
            print(f"  Commandes de sous-section récupérées sans indentation : {item['formatting_recovery_count']}")
    print(f"BILAN : {len(items)} fichiers | globales inconnues="
          f"{sum(x['unparsed_global_count'] for x in items)} | sous-sections opaques="
          f"{sum(x['nested_opaque_count'] for x in items)} | plateforme brute="
          f"{sum(x['source_only_counts']['platform_commands'] for x in items)}")
    print("PLATEFORME : modélisées="
          f"{sum(x['source_only_counts']['platform_modeled'] for x in items)} | "
          "sens à confirmer="
          f"{sum(x['source_only_counts']['platform_semantics_unverified'] for x in items)} | "
          "sémantique documentée (périmètre ancien)="
          f"{sum(x['source_only_counts']['platform_documented_scope_limited'] for x in items)} | "
          "non modélisées="
          f"{sum(x['source_only_counts']['platform_unmodeled'] for x in items)}")
    if args.json_summary:
        args.json_summary.parent.mkdir(parents=True, exist_ok=True)
        args.json_summary.write_text(json.dumps(items, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"Résumé sans commandes brutes : {args.json_summary}")
    if args.strict and any(x["unparsed_global_count"] or x["nested_opaque_count"] or
                           x["source_only_counts"]["platform_unmodeled"] for x in items):
        return 2
    if args.require_documented_platform and any(
        x["source_only_counts"]["platform_semantics_unverified"] or
        x["source_only_counts"]["platform_documented_scope_limited"] for x in items
    ):
        return 2
    if args.require_ios_family and any(not x["ios_family_compatible"] for x in items):
        return 2
    if args.require_export_evidence and any(
        x["source_format"] != "ios_15_classic_syntax_inferred" for x in items
    ):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
