# 6NLG — Phase 3 : adapter l'audit au parsing et à la normalisation Cisco IOS

## Pourquoi cette étape ?

Un `FAIL` ne doit jamais être confondu avec « le parseur n'a pas trouvé la
commande ». Notre chaîne distingue trois niveaux :

1. **Parsing** : identification des directives Cisco IOS dans le fichier source.
2. **Normalisation** : projection des informations reconnues dans l'IR JSON.
3. **Audit** : application d'une règle CIS *approuvée* sur un chemin IR précis.

Le nouveau module `audit_engine/ir_inventory.py` inventorie **53 parties
fonctionnelles**, réparties en **11 domaines**. La liste est volontairement
définie par le schéma du projet et ne prouve pas que toutes les variantes de
commandes IOS soient comprises.

| Domaine | Parties représentatives |
|---|---|
| Identité | hostname, version IOS |
| Plateforme | directives spécifiques de l'équipement |
| Réseau | VRF, interfaces, VLAN |
| Routage | routes statiques, OSPF, BGP |
| Politiques | ACL, prefix-lists, route-maps, community-lists |
| Services | NAT, pools NAT, DHCP |
| Supervision | SNMP, Syslog, buffers de journalisation |
| Temps | NTP, fuseau horaire |
| Sécurité IP | IP source routing, ICMP rate limit, TCP synwait |
| Administration | VTY/console, comptes, bannières, secrets, SSH, HTTP(S), AAA, RSA |
| Hors IR | wrappers CLI, métadonnées, services non modélisés, lignes inconnues |

Le rapport présente pour chaque partie : `parser_path`, `ir_path`,
`parser_count`, `ir_count`, éventuel contrôle CIS, ainsi qu'un statut :

- `AUDITED` : partie présente dans l'IR et contrôlée par une règle implémentée.
- `AUDITABLE_NOT_OBSERVED` : règle implémentée, mais valeur non observée.
- `IR_MAPPED` : normalisée, sans règle CIS encore implémentée.
- `PARSER_TO_IR_GAP` : présence dans le parsing mais absence de projection IR ;
  un traitement supplémentaire ou une justification s'impose.
- `SOURCE_ONLY` : information conservée dans les données du parsing mais
  délibérément non répliquée dans l'IR (risque de secrets, hors périmètre, etc.).
- `NOT_PRESENT` : aucune occurrence reconnue dans la configuration analysée.

Ces statuts mesurent la **couverture technique** ; ils ne sont pas des verdicts
de conformité du routeur.

## Audit sûr et preuves

Six recommandations CIS IOS 15 v4.1.1 sont reliées aux chemins IR existants.
Les contrôles explicitement satisfaits donnent `PASS` et les violations
explicitement visibles `FAIL`. Sans preuve de complétude, une déclaration
absente donne `UNKNOWN`. Avec `--assume-complete`, elle peut donner `FAIL`,
mais la preuve est étiquetée `assumed_absence`. Si des lignes globales non
interprétées, des sous-commandes opaques pertinentes ou des sections récupérées
incertaines risquent de cacher la déclaration, le résultat redevient `UNKNOWN`.

Le moteur n'affiche pas de mot de passe, de secret ou de configuration brute.

## Installer les modifications après les phases 1 et 2

Les fichiers remplacés par ce lot sont :

- `audit_engine/cis15_engine.py`
- `scripts/run_cis_ios15_audit.py`

Fichiers nouveaux : `audit_engine/ir_inventory.py`,
`tests/test_ir_inventory.py` et le présent document. Les modules `parsers/`,
`normalizers/` et `webapp/` ne sont **pas modifiés**.

Vérifier `git status --short` et les changements locaux avant d'accepter
les deux remplacements demandés par `unzip`.

```bash
cd ~/projet-6nlg/network-config-audit
source .venv/bin/activate
git status --short
unzip /mnt/c/Users/LENOVO/Downloads/audit_cisco_ios_phase3_inventaire_6nlg.zip
PYTHONPATH=parsers:.:scripts python3 -m unittest discover -s tests -p 'test_*.py' -q
```

Afficher toutes les parties dans le terminal et exporter les résultats :

```bash
PYTHONPATH=parsers:. python3 scripts/run_cis_ios15_audit.py \
  data/advanced_cases/isp_bgp_base/CE-1.cfg \
  --profile L2 --show-inventory \
  --output reports/cis_ios15_ce1_with_inventory.json
```

Le rapport comporte désormais `parsing_normalization_inventory` avec les
53 parties, leurs décomptes et leurs lacunes de couverture. Ajouter
`--assume-complete` uniquement après avoir validé l'intégralité de l'export.

## Suite de l'intégration

1. Faire valider les correspondances CIS et les profils par la revue humaine.
2. Pour chaque nouvelle recommandation, identifier d'abord son chemin IR ;
   compléter le parseur et le normaliseur uniquement si nécessaire.
3. Ajouter un test conforme et un test non conforme, ainsi qu'un test
   d'incertitude (ligne manquante ou non reconnue) pour chaque règle.
4. Ajouter le rapport d'audit et la matrice de couverture dans l'interface
   Flask en conservant la distinction `FAIL` / `UNKNOWN`.

**Périmètre actuel :** 6 contrôles CIS actifs sur 53 parties inventoriées,
et non 53 contrôles CIS ni une certification globale du benchmark.
