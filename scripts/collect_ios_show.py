"""Collecter uniquement une liste fixe de commandes show sur Cisco IOS via SSH.

Lecture seule au niveau des commandes envoyées. Utiliser un compte autorisé
et limité à la consultation sur le routeur. Aucun raw show n'est stocké.
"""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
from pathlib import Path

from audit_engine.show_evidence import ALLOWED_SHOW_COMMANDS, summarize_show_outputs


def main() -> None:
    cli = argparse.ArgumentParser(description="Collecte Cisco IOS SHOW, jamais de configuration")
    cli.add_argument("--host", required=True, help="Adresse IP de l'équipement explicitement autorisé")
    cli.add_argument("--username", required=True)
    cli.add_argument("--expected-hostname", required=True,
                     help="Hostname attendu (vérifié ensuite par le moteur d'audit)")
    cli.add_argument("--port", type=int, default=22)
    cli.add_argument("--output", type=Path, required=True)
    cli.add_argument("--dry-run", action="store_true", help="Afficher les commandes sans connexion")
    args = cli.parse_args()
    try:
        ipaddress.ip_address(args.host)
    except ValueError as exc:
        cli.error("--host doit être une adresse IPv4/IPv6 explicite : " + str(exc))
    if not 1 <= args.port <= 65535:
        cli.error("Port SSH invalide")
    print("Cible autorisée :", args.host, "| compte :", args.username)
    for command in ALLOWED_SHOW_COMMANDS:
        print("  READ-ONLY:", command)
    if args.dry_run:
        print("Dry-run terminé : aucune connexion établie")
        return
    try:
        from netmiko import ConnectHandler  # pip install -r requirements-show.txt
    except ImportError as exc:
        cli.error("Installer Netmiko : pip install -r requirements-show.txt")
        raise AssertionError from exc
    password = getpass.getpass("Mot de passe SSH (non stocké) : ")
    responses = {}
    # Un compte IOS de consultation (sans droit de configuration) est recommandé.
    with ConnectHandler(
        device_type="cisco_ios", host=args.host, username=args.username,
        password=password, port=args.port, ssh_strict=True, system_host_keys=True,
        timeout=20, auth_timeout=20, banner_timeout=20,
    ) as connection:
        for command in ALLOWED_SHOW_COMMANDS:
            print("Consultation :", command)
            try:
                responses[command] = connection.send_command(command, read_timeout=25)
            except Exception:
                # Aucune erreur contenant du trafic ou des identifiants n'est affichée.
                print("  Commande non disponible ou délai dépassé")
    summary = summarize_show_outputs(responses, hostname=args.expected_hostname, target=args.host)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("Preuves non sensibles enregistrées :", args.output)


if __name__ == "__main__":
    main()
