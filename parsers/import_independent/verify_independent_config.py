"""Assert expected extraction from synthetic independent IOS fixture.

Run from network-config-audit as:
PYTHONPATH=parsers python3 tests/verify_independent_config.py data/validation/test_router_independent.cfg
"""

import sys
from pathlib import Path

from cisco_parser import parse_cisco_ios


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data/validation/test_router_independent.cfg")
    if not path.is_file():
        print(f"Fichier introuvable : {path}", file=sys.stderr)
        return 2

    result = parse_cisco_ios(path.read_text(encoding="utf-8"))
    assert result["hostname"] == "LAB-AUDIT-R1"
    print("[PASS] hostname : LAB-AUDIT-R1")

    interfaces = result["interfaces"]
    assert len(interfaces) == 3
    loopback = next(i for i in interfaces if i["name"] == "Loopback0")
    assert loopback["ipv4_addresses"][0]["address"] == "10.255.0.1"
    print("[PASS] interfaces : 3, Loopback0 : 10.255.0.1")

    ospf = result["ospf_processes"]
    assert len(ospf) == 1
    assert ospf[0]["process_id"] == "10"
    assert ospf[0]["router_id"] == "10.255.0.1"
    assert len(ospf[0]["networks"]) == 3
    assert set(ospf[0]["passive_interfaces"]) == {"Loopback0", "GigabitEthernet0/0"}
    print("[PASS] OSPF : processus 10, 3 réseaux, 2 interfaces passives")

    routes = result["static_routes"]
    assert len(routes) == 2
    assert any(r["destination"] == "172.16.20.0" and r["administrative_distance_configured"] == 150 for r in routes)
    assert any(r["destination"] == "0.0.0.0" and r["mask"] == "0.0.0.0" for r in routes)
    print("[PASS] routes statiques : 2 dont une route AD=150")

    assert len(result["access_lists"]) == 1
    assert result["access_lists"][0]["name"] == "20"
    print("[PASS] ACL standard : 20")

    assert len(result["snmp"]["communities"]) == 1
    assert result["snmp"]["communities"][0]["access"] == "RO"
    assert len(result["snmp"]["hosts"]) == 1
    assert result["snmp"]["hosts"][0]["version"] == "2c"
    print("[PASS] SNMP : communauté RO et destination v2c")

    assert len(result["syslog"]["hosts"]) == 1
    assert result["syslog"]["source_interface"] == "Loopback0"
    assert result["syslog"]["trap_level"] == "warnings"
    print("[PASS] Syslog : 1 serveur, source Loopback0, niveau warnings")

    print("VALIDATION INDÉPENDANTE : 7/7 CONTRÔLES RÉUSSIS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
