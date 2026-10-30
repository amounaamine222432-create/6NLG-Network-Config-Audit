# NetAudit 6NLG — Phase 4, extension des contrôles CIS Cisco IOS 15

Cette archive complète les phases 1, 2 et 3. Elle ajoute **20 contrôles**
au socle de six règles : **26 règles statiques** associées à la version
archivée **CIS Cisco IOS 15 Benchmark v4.1.1**.

Le document de référence a été vérifié localement : 214 pages, SHA-256
`7a54074e91143d1ad6ecea3964d1ed4948775d01a863cfb53ab54d1facd4ed34`.
Le PDF n'est pas redistribué dans ce ZIP. Les contrôles restent **expérimentaux**
et ne constituent pas une certification CIS.

## Matrice des règles ajoutées

| Domaine | Contrôle CIS | Profil | Preuve dans l'IR |
|---|---|---|---|
| Administration | 1.1.1 | L1 | `management.aaa_new_model_enabled` |
| Administration | 1.2.7 | L1 | `management.terminal_lines[].exec_timeout`, console |
| Administration | 1.2.9 | L1 | `management.terminal_lines[].exec_timeout`, VTY |
| Administration | 1.3.2, 1.3.3 | L1 | `management.banners`, login et MOTD |
| Administration | 1.4.3 | L1 | `management.local_accounts[].credential_type` |
| Administration | 2.1.1.2 | L1 | `management.ssh_version` |
| SNMP | 1.5.4 | L1 | `services.snmp.communities[].access` |
| SNMP | 1.5.9 | L2 | `services.snmp.groups[].security_level` |
| Syslog | 2.2.2, 2.2.4, 2.2.5 | L1 | `buffered`, `targets`, `severity` |
| NTP | 2.3.1.2, 2.3.1.3, 2.3.1.4 | L2 | clés, clés fiables, serveur avec clé |
| NTP | 2.3.2 | L1 | `services.ntp.servers` |
| NTP | 2.4.3 | L2 | `services.ntp.source_interface` |
| Sécurité réseau | 3.1.2, 3.1.3 | L2 | `interfaces[].proxy_arp_enabled`, interface Tunnel |
| Routage BGP | 3.3.4.1 | L2 | `routing.bgp[].neighbors[].password_configured` |

Les six règles précédentes (1.2.2, 1.3.1, 1.4.1, 2.2.7, 2.3.1.1 et 3.1.1)
restent disponibles. Les 26 contrôles se trouvent dans
`benchmarks/rules/cisco_ios/cis_ios15_v4.1.1_extended_lab.json`.

## Améliorations du parsing et de l'IR

- Extraction explicite de `aaa new-model` et des versions SSH 1/2 dans l'IR.
- Reconnaissance de `ip proxy-arp` et `no ip proxy-arp` sur les interfaces.
- Présence d'un mot de passe BGP par voisin ou héritage de peer-group ; **la
  valeur du mot de passe n'est plus conservée dans le JSON du parseur**.
- Valeurs des communautés SNMP également expurgées du JSON de parsing.
- Inventaire étendu à **55 parties** réparties en 11 domaines, avec 26 règles
  liées à 18 parties.
- Schéma formel de l'IR mis à jour pour `management.aaa_new_model_enabled`.

## Interprétation prudente

- Une temporisation EXEC absente de `running-config` reste `UNKNOWN`, même
  avec `--assume-complete`, parce qu'une valeur par défaut IOS peut ne pas
  apparaître dans le fichier. Un timeout explicite de `0 0` est un `FAIL`.
- Un réglage explicite (AAA désactivé, Telnet autorisé, communauté SNMP RW,
  interface Tunnel, etc.) peut donner un `FAIL` sans hypothèse de complétude.
- Une absence supposée ne peut donner `FAIL` que si l'utilisateur confirme
  l'export complet ; le rapport marque alors `assumed_absence`.
- Une option non reconnue ou une commande globale non interprétée peut
  convertir un `FAIL` déduit d'absence en `UNKNOWN`.
- Les contrôles `show ip ssh`, `show ip interface`, `show ntp associations`,
  `show snmp group` et la validation des ACL appliquées au périmètre externe
  nécessitent une **collecte opérationnelle** distincte pour un audit exhaustif.
- Les contrôles SNMP sont évalués seulement lorsqu'ils sont applicables à des
  communautés ou groupes explicitement présents ; l'absence peut renvoyer
  `NOT_APPLICABLE` si la configuration est complète.

Le moteur ne prend **aucune action de configuration** sur le routeur.

## Installation depuis WSL

Dans le dépôt local contenant les trois premières phases :

```bash
cd ~/projet-6nlg/network-config-audit
source .venv/bin/activate

# Inspecter les fichiers existants avant tout remplacement :
unzip -l /mnt/c/Users/LENOVO/Downloads/audit_cisco_ios_phase4_cis15_6nlg.zip

# Remplacer les fichiers de phase précédente après confirmation interactive :
unzip /mnt/c/Users/LENOVO/Downloads/audit_cisco_ios_phase4_cis15_6nlg.zip

PYTHONPATH=parsers:.:scripts python3 -m unittest discover \
  -s tests -p 'test_*.py' -q
```

**Attention :** plusieurs fichiers du parseur, normaliseur, moteur et tests
sont actualisés ; ne pas répondre « tout remplacer » sans vérifier les
modifications locales. `git status` peut échouer si le projet n'est pas encore
un dépôt Git : ce n'est pas un problème pour le fonctionnement du code.

### Lancer l'analyse étendue

```bash
PYTHONPATH=parsers:. python3 scripts/run_cis_ios15_audit.py \
  data/advanced_cases/isp_bgp_base/CE-1.cfg \
  --profile L2 --show-inventory \
  --output reports/cis_ios15_ce1_phase4.json
```

Utiliser `--profile L1` pour les 17 contrôles L1, `--profile L2` pour les
26 contrôles. L'option `--assume-complete` est facultative et réservée aux
exports complets confirmés. L'ancienne sélection de six règles reste possible :

```bash
PYTHONPATH=parsers:. python3 scripts/run_cis_ios15_audit.py \
  data/advanced_cases/isp_bgp_base/CE-1.cfg \
  --catalogue benchmarks/rules/cisco_ios/cis_ios15_v4.1.1_lab.json
```

## Vérifications réalisées

- Tests sur un exemple explicite avec **26 PASS** en profil L2.
- Tests de contre-exemples : AAA désactivé, Telnet, timeout infini, SNMP RW,
  SNMPv3 sans priv, SSHv1, proxy ARP, tunnel, source routing activé.
- Tests d'héritage de mot de passe BGP depuis un peer-group.
- Tests des cas `UNKNOWN`, `NOT_SELECTED`, `NOT_APPLICABLE` et des secrets
  expurgés.

## Suite proposée

1. Vérifier la documentation Cisco du modèle et la version IOS exacte,
   au-delà du simple texte `version 15.x`.
2. Étendre le parseur aux preuves manquantes : AAA accounting, restrictions
   VTY, protection OSPF/EIGRP, uRPF et ACL anti-spoofing.
3. Ajouter une collecte en lecture seule des commandes `show` nécessaires.
4. Intégrer les résultats et la couverture dans Flask sans présenter ces
   résultats comme une certification CIS complète.
