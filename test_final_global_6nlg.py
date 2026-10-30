"""Test d'intégration reproductible : Cisco IOS -> Parsing -> IR -> HTML.

À placer à la racine de network-config-audit avec R-6NLG-GLOBAL-TEST-01.cfg.
Exécution : python3 test_final_global_6nlg.py

Cas synthétique de régression. Il ne prouve pas une couverture exhaustive des
versions Cisco IOS et ne vérifie aucun équipement en fonctionnement.
"""

from __future__ import annotations

from io import BytesIO
from pathlib import Path
import re
import sys

from webapp import create_app


ROOT = Path(__file__).resolve().parent
CONFIG = ROOT / "R-6NLG-GLOBAL-TEST-01.cfg"
PASSED = 0
FAILED = 0


def check(label: str, condition: bool) -> None:
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"[OK] {label}")
    else:
        FAILED += 1
        print(f"[ECHEC] {label}")


def main() -> int:
    if not CONFIG.is_file():
        print(f"Fichier de test absent : {CONFIG}")
        return 2

    client = create_app({"TESTING": True}).test_client()
    home = client.get("/")
    csrf_match = re.search(rb'<meta name="csrf-token" content="([^"]+)"', home.data)
    check("Page Flask et formulaire CSRF", home.status_code == 200 and csrf_match is not None)
    if csrf_match is None:
        return 2

    response = client.post(
        "/api/analyze",
        data={"files": (BytesIO(CONFIG.read_bytes()), CONFIG.name)},
        content_type="multipart/form-data",
        headers={"X-CSRF-Token": csrf_match.group(1).decode("ascii")},
    )
    payload = response.get_json(silent=True) or {}
    check("Import et analyse Flask", response.status_code == 200 and payload.get("ok"))
    if not payload.get("ok"):
        print(payload)
        return 1

    metrics = payload["metrics"]
    for field, expected in {"devices": 1, "interfaces": 8, "ospf": 1, "bgp": 1,
                            "unknowns": 0}.items():
        check(f"Métrique {field} = {expected}", metrics.get(field) == expected)

    device = payload["devices"][0]
    for field, expected in {"acl": 2, "nat": 1, "dhcp_pools": 1, "hsrp": 1,
                            "static_routes": 2, "vrf": 1, "route_maps": 1,
                            "prefix_lists": 1, "snmp_communities": 1,
                            "syslog_hosts": 1}.items():
        check(f"Détection {field} = {expected}", device["counts"].get(field) == expected)
    check("Aucune sous-section opaque", device["coverage"]["nested_unknown"] == 0)
    check("Aucune directive plateforme inconnue", device["coverage"]["platform_unknown"] == 0)

    files = {}
    for kind in ("parsing", "ir", "html", "summary"):
        output = client.get(payload["downloads"][kind])
        check(f"Téléchargement {kind}", output.status_code == 200)
        files[kind] = output.get_data(as_text=True)
    parsed_payload = client.get(f'/api/view/{payload["run_id"]}/parsing').get_json()
    ir_payload = client.get(f'/api/view/{payload["run_id"]}/ir').get_json()
    html_preview = client.get(f'/api/view/{payload["run_id"]}/html')
    check("Prévisualisation HTML intégrée", html_preview.status_code == 200)
    check("Prévisualisation HTML limitée à la même origine",
          html_preview.headers.get("X-Frame-Options") == "SAMEORIGIN")

    if not (parsed_payload and ir_payload):
        print("Erreur : sorties JSON manquantes")
        return 1
    parsed = parsed_payload["devices"][0]["parsed"]
    ir = ir_payload["devices"][0]["ir"]
    check("Parsing : hostname conservé", parsed["hostname"] == "R-6NLG-GLOBAL-TEST-01")
    check("Parsing : huit interfaces", len(parsed["interfaces"]) == 8)
    check("Parsing : VLAN", len(parsed["vlans"]) == 3)
    check("Parsing : OSPF", len(parsed["ospf_processes"]) == 1)
    check("Parsing : BGP", len(parsed["bgp_processes"]) == 1)
    check("Parsing : ACL et route-map", len(parsed["access_lists"]) == 2 and len(parsed["route_maps"]) == 1)

    check("IR : hostname conservé", ir["device"]["hostname"] == parsed["hostname"])
    check("IR : huit interfaces", len(ir["interfaces"]) == len(parsed["interfaces"]))
    check("IR : VLAN, ACL, route-map", len(ir["services"]["vlans"]) == 3
          and len(ir["policies"]["acls"]) == 2 and len(ir["policies"]["route_maps"]) == 1)
    check("IR : OSPF/BGP et routes", len(ir["routing"]["ospf"]) == 1
          and len(ir["routing"]["bgp"]) == 1 and len(ir["routing"]["static_routes"]) == 2)
    cidrs = {ip["cidr"] for item in ir["interfaces"] for ip in item["ipv4_addresses"]}
    check("IR : normalisation CIDR", {"10.10.10.1/24", "203.0.113.2/30"}.issubset(cidrs))
    check("IR : absence de faux état opérationnel",
          all(item.get("operational_state") is None for item in ir["interfaces"]))

    html = files["html"]
    for section in ("Bilan technique", "Interfaces réseau et adressage", "OSPF", "BGP", "ACL",
                    "NAT", "DHCP", "VLAN", "HSRP", "SNMP", "Syslog", "route-map EXPORT_FILTER",
                    "Contrôles d'audit et recommandations"):
        check(f"Rapport HTML : {section}", section in html)

    for marker in ("DEMO_ONLY_NOT_A_REAL_SECRET", "DEMO_ONLY_REDACTED", "DEMO_ONLY_AUTH_KEY"):
        check(f"Secret de démonstration masqué : {marker}",
              all(marker not in output for output in files.values()))

    print(f"\nBILAN FINAL : {PASSED} vérifications réussies / {PASSED + FAILED} ; "
          f"{FAILED} échec(s)")
    print("Portée : extraction, IR et restitution HTML d'un cas synthétique global.")
    if FAILED:
        return 1
    print("Statut : TEST D'INTÉGRATION VALIDÉ (ne vaut pas certification du réseau).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
