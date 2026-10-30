"""Generate 30 deterministic, synthetic IOS 15 configurations and independent references.

The golden facts below are derived from deliberately selected scenario parameters,
not from the parser or normalizer under evaluation.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CASES = ROOT / "configs"
GOLD = ROOT / "gold"


def make_case(index):
    group = "OK" if index <= 10 else "FAIL" if index <= 20 else "MIXED" if index <= 25 else "PARTIAL"
    hostname = f"R-BENCH-{group}-{index:02d}"
    secure = group == "OK"
    bad = group == "FAIL"
    mixed = group == "MIXED"
    # Five deliberately different incomplete excerpts; no absent fact is treated as false.
    partial = group == "PARTIAL"
    octet = index
    wan = f"198.51.100.{octet * 4 + 1}"
    gateway = f"198.51.100.{octet * 4 + 2}"
    lan = f"10.{octet}.0.1"
    facts = []
    commands = ["version 15.2", f"hostname {hostname}"]

    def fact(category, value):
        facts.append(f"{category}={value}")

    fact("hostname", hostname)
    fact("ios", "15.2")
    if not partial or index in (26, 28, 30):
        source_routing = bad or (mixed and index % 2 == 0)
        commands.append("ip source-route" if source_routing else "no ip source-route")
        fact("source_route", str(source_routing).lower())

    if not partial or index == 28:
        aaa = not bad
        commands.append("aaa new-model" if aaa else "no aaa new-model")
        fact("aaa", str(aaa).lower())
        if aaa:
            commands.append("aaa authentication login default local")
        ssh = not bad
        if ssh:
            commands.append("ip ssh version 2")
            fact("ssh_version", "2")

    if not partial or index in (26, 27, 29):
        commands.extend([
            "!", "interface GigabitEthernet0/0", " description WAN",
            f" ip address {wan} 255.255.255.252",
            " ip proxy-arp" if bad or (mixed and index % 2 == 1) else " no ip proxy-arp",
            " no shutdown",
        ])
        fact("interface", f"GigabitEthernet0/0|{wan}/30")
        if not partial or index == 29:
            commands.extend([
                "!", "interface GigabitEthernet0/1", " description LAN",
                f" ip address {lan} 255.255.255.0", " no ip proxy-arp", " no shutdown",
            ])
            fact("interface", f"GigabitEthernet0/1|{lan}/24")

    if not partial or index in (27, 30):
        commands.append(f"ip route 0.0.0.0 0.0.0.0 {gateway}")
        fact("route", f"0.0.0.0/0|{gateway}")

    if not partial or index in (26, 28):
        if not bad:
            # On purpose: inline banner followed immediately by VTY/console.
            commands.append("banner motd ^CAccess restricted^C")
            fact("banner", "motd")
        for identifier, timeout in (("con 0", 5), ("vty 0 4", 15 if mixed else 5 if secure else 0),
                                    ("vty 5 15", 5 if secure else 15 if mixed else 0)):
            commands.append("line " + identifier)
            commands.append(f" exec-timeout {timeout} 0")
            fact("timeout", f"{identifier}|{timeout * 60}")
            if identifier.startswith("vty"):
                transport = "ssh" if not bad else "telnet"
                commands.append(" transport input " + transport)
                fact("transport", f"{identifier}|{transport}")
            commands.append(" login authentication default" if not bad else " login")
            fact("login", f"{identifier}|{'authentication default' if not bad else 'line_password'}")

    if not partial or index == 30:
        if bad:
            commands.append("snmp-server community labreadonly RO")
            commands.append("snmp-server community labwrite RW")
            fact("snmp_access", "RO")
            fact("snmp_access", "RW")
        else:
            commands.append("snmp-server community labreadonly RO")
            fact("snmp_access", "RO")
    if secure or mixed:
        size = 64000 if secure else 8192
        commands.append(f"logging buffered {size} informational")
        fact("syslog_buffer", str(size))
        commands.append("logging host 192.0.2.20")
        fact("syslog_host", "192.0.2.20")
        commands.append("ntp server 192.0.2.30")
        fact("ntp_server", "192.0.2.30")

    commands.append("end")
    return group, hostname, "\n".join(commands) + "\n", sorted(facts)


def main():
    CASES.mkdir(exist_ok=True)
    GOLD.mkdir(exist_ok=True)
    manifest = []
    for i in range(1, 31):
        group, hostname, config, facts = make_case(i)
        name = f"{i:02d}_{group}.cfg"
        (CASES / name).write_text(config, encoding="utf-8")
        (GOLD / (name + ".json")).write_text(json.dumps({"facts": facts}, indent=2) + "\n", encoding="utf-8")
        manifest.append({"filename": name, "group": group, "hostname": hostname, "fact_count": len(facts)})
    (ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print("Generated", len(manifest), "configs and independent golden references")


if __name__ == "__main__":
    main()
