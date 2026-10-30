"""30 cas synthétiques ciblés, avec oracles explicites indépendants du parseur.

Les attentes sont écrites depuis les paramètres des scénarios, jamais depuis
la sortie du parseur. Elles doivent faire l'objet d'une revue humaine.
"""
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent


def make_cases():
    cases = []
    for i in range(5):
        n = i + 1
        name = f"ACL_{n:02d}"
        log = " log" if i % 2 == 0 else ""
        snippet = f"ip access-list extended WEB-{n}\n deny ip 10.{n}.0.0 0.0.255.255 any{log}\n permit tcp any host 198.51.100.{n} eq 443{log}"
        cases.append((name, "ACL", snippet,
            {"access_lists.0.name": f"WEB-{n}", "access_lists.0.entries.0.action": "deny",
             "access_lists.0.entries.1.protocol": "tcp", "access_lists.0.entries.1.logging_mode": "log" if log else None},
            {"policies.acls.0.name": f"WEB-{n}", "policies.acls.0.entries.0.action": "deny",
             "policies.acls.0.entries.1.protocol": "tcp", "policies.acls.0.entries.1.logging_mode": "log" if log else None}))
    for i in range(5):
        n = i + 1
        if i < 3:
            snippet = f"router ospf {100+n}\n router-id 10.{n}.0.1\n network 10.{n}.0.0 0.0.255.255 area {n}\n area {n} authentication message-digest"
            pa = {"ospf_processes.0.process_id": str(100+n), "ospf_processes.0.networks.0.area": str(n)}
            ia = {"routing.ospf.0.process_id": str(100+n), "routing.ospf.0.network_selectors.0.area": str(n)}
        else:
            aut = "auto-summary" if i == 3 else "no auto-summary"
            snippet = f"router eigrp {100+n}\n network 10.{n}.0.0 0.0.255.255\n {aut}"
            pa = {"eigrp_processes.0.identifier": str(100+n)}
            ia = {"routing.eigrp.0.identifier": str(100+n), "routing.eigrp.0.auto_summary_enabled": i == 3}
        cases.append((f"ROUTING_{n:02d}", "ROUTING", snippet, pa, ia))
    for i in range(5):
        n = i + 1
        snippet = f"router bgp {65100+n}\n bgp router-id 10.{n}.0.1\n neighbor 192.0.2.{n} remote-as {65200+n}\n network 10.{n}.0.0 mask 255.255.0.0"
        cases.append((f"BGP_{n:02d}", "BGP", snippet,
            {"bgp_processes.0.local_as": str(65100+n), "bgp_processes.0.neighbors.0.remote_as": str(65200+n)},
            {"routing.bgp.0.local_as": 65100+n, "routing.bgp.0.neighbors.0.remote_as": 65200+n,
             "routing.bgp.0.network_statements.0.prefix": f"10.{n}.0.0/16"}))
    for i in range(5):
        n = i + 1
        snippet = f"ip dhcp excluded-address 10.{n}.10.1 10.{n}.10.10\nip dhcp pool POOL-{n}\n network 10.{n}.10.0 255.255.255.0\n default-router 10.{n}.10.1\n dns-server 192.0.2.53\nip nat inside source static 10.{n}.10.20 203.0.113.{n}"
        cases.append((f"DHCP_NAT_{n:02d}", "DHCP_NAT", snippet,
            {"dhcp_pools.0.name": f"POOL-{n}", "nat_rules.0.inside_local": f"10.{n}.10.20"},
            {"services.dhcp.pools.0.name": f"POOL-{n}", "services.dhcp.pools.0.subnet": f"10.{n}.10.0/24",
             "services.nat.rules.0.inside_global": f"203.0.113.{n}"}))
    for i in range(5):
        n = i + 1
        snippet = f"vrf definition SITE-{n}\n rd 65000:{n}\nvlan {200+n}\n name VLAN-{n}\ninterface GigabitEthernet0/{n}\n description VRF LINK\n vrf forwarding SITE-{n}\n no shutdown"
        cases.append((f"VLAN_VRF_{n:02d}", "VLAN_VRF", snippet,
            {"vrfs.0.name": f"SITE-{n}", "vlans.0.name": str(200+n), "interfaces.0.name": f"GigabitEthernet0/{n}"},
            {"vrfs.0.name": f"SITE-{n}", "services.vlans.0.id": 200+n, "interfaces.0.vrf": f"SITE-{n}"}))
    for i in range(5):
        n = i + 1
        snippet = f"ip route 10.{n}.0.0 255.255.0.0 192.0.2.{n}\nip route 0.0.0.0 0.0.0.0 198.51.100.{n}"
        cases.append((f"STATIC_{n:02d}", "STATIC", snippet,
            {"static_routes.0.destination": f"10.{n}.0.0", "static_routes.1.next_hop": f"198.51.100.{n}"},
            {"routing.static_routes.0.prefix": f"10.{n}.0.0/16", "routing.static_routes.1.prefix": "0.0.0.0/0"}))
    return cases


def main():
    configs = HERE / "configs"
    configs.mkdir(parents=True, exist_ok=True)
    records = []
    for name, family, body, parser_expected, ir_expected in make_cases():
        source = f"version 15.2\nhostname R-{name}\n{body}\nend\n"
        (configs / f"{name}.cfg").write_text(source, encoding="utf-8")
        records.append({"file": f"{name}.cfg", "family": family,
                        "parser_expected": parser_expected, "ir_expected": ir_expected})
    (HERE / "expected.json").write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    print(f"Prepared {len(records)} cases")


if __name__ == "__main__":
    main()
