"""Corpus validation report for the user's actual Batfish and C4Geeks files.


Run in network-config-audit with PYTHONPATH=parsers and both data folders.
Not a substitute for command-level ground-truth checks.
"""

import argparse
from pathlib import Path

from cisco_parser import parse_cisco_ios


def count_features(parsed):
    ifaces = parsed["interfaces"]
    return {
        "interfaces": len(ifaces),
        "ospf": len(parsed["ospf_processes"]),
        "bgp": len(parsed["bgp_processes"]),
        "static_routes": len(parsed["static_routes"]),
        "access_lists": len(parsed["access_lists"]),
        "prefix_lists": len(parsed["prefix_lists"]),
        "route_maps": len(parsed["route_maps"]),
        "nat_rules": len(parsed["nat_rules"]),
        "nat_pools": len(parsed["nat_pools"]),
        "nat_interfaces": sum(bool(i["nat_role"]) for i in ifaces),
        "dot1q": sum(bool(i["dot1q"]) for i in ifaces),
        "switchports": sum(bool(i["switchport"]["mode"]) for i in ifaces),
        "hsrp_groups": sum(len(i["hsrp_groups"]) for i in ifaces),
        "dhcp_relays": sum(len(i["ip_helper_addresses"]) for i in ifaces),
        "dhcp_pools": len(parsed["dhcp_pools"]),
        "snmp_communities": len(parsed["snmp"]["communities"]),
        "snmp_hosts": len(parsed["snmp"]["hosts"]),
        "syslog_hosts": len(parsed["syslog"]["hosts"]),
    }


def inspect_folder(root):
    files = sorted(f for f in root.rglob("*") if f.suffix.lower() in (".cfg", ".txt") and f.is_file())
    totals = {}
    details = {}
    warnings = []
    for f in files:
        parsed = parse_cisco_ios(f.read_text(encoding="utf-8-sig"))
        features = count_features(parsed)
        relative = str(f.relative_to(root))
        details[relative] = features
        if not parsed["hostname"]:
            warnings.append(f"Hostname absent : {relative}")
        for field, count in features.items():
            totals[field] = totals.get(field, 0) + count
    return files, totals, details, warnings


def main():
    cli = argparse.ArgumentParser(description="Vérifier Batfish + C4Geeks")
    cli.add_argument("--batfish", type=Path, default=Path("data/pybatfish_full"))
    cli.add_argument("--c4geeks", type=Path, default=Path("data/c4geeks"))
    args = cli.parse_args()

    for name, path in (("Batfish", args.batfish), ("C4Geeks", args.c4geeks)):
        if not path.is_dir():
            cli.error(f"Dossier {name} introuvable : {path}")

    b_files, b_total, b_detail, b_warnings = inspect_folder(args.batfish)
    c_files, c_total, c_detail, c_warnings = inspect_folder(args.c4geeks)
    print(f"BATFISH : {len(b_files)} fichiers")
    for key, value in b_total.items():
        if value:
            print(f"  {key}: {value}")
    print(f"C4GEEKS : {len(c_files)} fichiers")
    for key, value in c_total.items():
        if value:
            print(f"  {key}: {value}")

    checks = {
        "nat-pat/R1-config.txt": ("nat_rules", "nat_pools", "nat_interfaces"),
        "hsrp/R1-hsrp.txt": ("hsrp_groups",),
        "router-on-a-stick/R1-config.txt": ("dot1q",),
        "dhcp-server-relay/R1-config.txt": ("dhcp_pools",),
        "dhcp-server-relay/R2-config.txt": ("dhcp_relays",),
        "snmp-syslog/R1-config.txt": ("snmp_communities", "syslog_hosts"),
        "static-routing-ipv4/R1-config.txt": ("static_routes",),
    }
    failed = []
    for name, required in checks.items():
        if name not in c_detail:
            print(f"NON TESTÉ : {name} absent du corpus")
            continue
        for field in required:
            n = c_detail[name][field]
            result = "OK" if n else "À INSPECTER"
            print(f"{result}: {name} → {field}={n}")
            if not n:
                failed.append(f"{name} → {field}")

    if len(b_files) == 13:
        for field, expected in {"interfaces": 65, "ospf": 12, "bgp": 13}.items():
            if b_total.get(field) != expected:
                failed.append(f"Batfish: {field} attendu {expected}, trouvé {b_total.get(field)}")
    print(f"Hostname avertissements : {len(b_warnings) + len(c_warnings)}")
    for warning in b_warnings + c_warnings + failed:
        print(f"ATTENTION : {warning}")
    if failed:
        print("VALIDATION CIBLÉE : À COMPLÉTER")
        return 1
    print("VALIDATION CIBLÉE : OK (couverture limitée aux critères affichés)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
