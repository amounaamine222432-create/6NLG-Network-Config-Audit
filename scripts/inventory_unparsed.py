#!/usr/bin/env python3
"""Inventorier les commandes globales encore inconnues, sans valeurs sensibles.

Lance depuis la racine du projet: PYTHONPATH=parsers python3 scripts/inventory_unparsed.py data/pybatfish_full data/c4geeks
"""

import argparse
from collections import Counter
from pathlib import Path
import sys

try:
    from cisco_parser import parse_cisco_ios
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "parsers"))
    from cisco_parser import parse_cisco_ios


# Seuls les mots-clés littéraux sont imprimés. Tout nom, IP, chemin, mot de
# passe, communauté, clé et argument libre est remplacé par <ARGUMENT>.
SAFE_WORDS = {
    "no", "ip", "ipv6", "tcp", "icmp", "rate-limit", "unreachable",
    "synwait-time", "bgp-community", "new-format", "domain-name",
    "domain", "name", "ntp", "server", "peer", "source", "trusted-key",
    "authentication-key", "authenticate", "master", "clock-period",
    "access-group", "update-calendar", "logging", "enable", "secret",
    "password", "aaa", "authentication", "login", "privilege-mode",
    "crypto", "key", "generate", "rsa", "modulus", "multicast-routing",
    "classless", "forward-protocol", "boot", "service", "timestamps",
    "archive", "path", "time-period", "snmp-server", "community",
    "username", "router", "ospf", "bgp", "system", "no-access",
    "spanning-tree", "mode", "rapid-pvst", "version", "dot1x",
    "logging", "event", "terminal", "monitor", "trap", "console",
}


def command_signature(command: str) -> str:
    words = command.split()
    safe = []
    for word in words[:7]:
        if word.lower() not in SAFE_WORDS:
            safe.append("<ARGUMENT>")
            break
        safe.append(word.lower())
    if len(words) > len(safe) and (not safe or safe[-1] != "<ARGUMENT>"):
        safe.append("<ARGUMENT>")
    return " ".join(safe) if safe else "<COMMANDE>"


def main() -> int:
    cli = argparse.ArgumentParser(description="Inventaire sans secrets des directives Cisco non parsees")
    cli.add_argument("sources", nargs="+", type=Path, help="Fichiers .cfg/.txt ou dossiers")
    args = cli.parse_args()
    total = 0
    frequency = Counter()
    for src in args.sources:
        if not src.exists():
            cli.error(f"Source introuvable : {src}")
        files = (sorted(p for p in src.rglob("*") if p.is_file() and p.suffix.lower() in {".cfg", ".txt"})
                 if src.is_dir() else [src])
        for file in files:
            parsed = parse_cisco_ios(file.read_text(encoding="utf-8-sig"))
            unknown = parsed.get("unparsed_lines") or []
            if unknown:
                print(f"{file}: {len(unknown)} lignes non parsees")
            total += len(unknown)
            frequency.update(command_signature(item["command"]) for item in unknown)
    print("\nFAMILLES NON CLASSEES (arguments masques) :")
    for signature, count in frequency.most_common():
        print(f"{count:4} x {signature}")
    print(f"TOTAL : {total} lignes globales non parsees")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
