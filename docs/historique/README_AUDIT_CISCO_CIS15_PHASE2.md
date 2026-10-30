# 6NLG — CIS Cisco IOS 15, première évaluation sur IR (phase 2)

Ce lot **complète** la phase 1 sans modifier `cisco_parser.py`,
`cisco_normalizer.py` ni l'application Flask. Il contient six références
contrôlées dans le benchmark fourni par l'équipe, **pas l'intégralité** de la
norme et **pas une certification**.

## Document et périmètre

- Document : CIS Cisco IOS 15 Benchmark, v4.1.1 (archive ; 214 pages).
- SHA-256 du PDF examiné : `7a54074e91143d1ad6ecea3964d1ed4948775d01a863cfb53ab54d1facd4ed34`.
- L'extracteur PDF récupère 89 recommandations candidates avec leurs sections
  Audit/Remediation ; elles restent `review_required`. Le PDF n'est pas inclus.
- Six recommandations ont fait l'objet d'une correspondance expérimentale
  avec le schéma IR existant et de tests ciblés.

| CIS | Profil | Valeur IR contrôlée |
|---|---|---|
| 1.2.2 | L1 | `management.terminal_lines`: VTY uniquement SSH |
| 1.3.1 | L1 | `management.banners`: présence de `exec` |
| 1.4.1 | L1 | `management.enable_secret_configured` |
| 2.2.7 | L1 | `services.syslog.source_interface` |
| 2.3.1.1 | L2 | `services.ntp.authentication_enabled` |
| 3.1.1 | L1 | `services.ip_stack.source_route_enabled` |

## Installation WSL

Depuis le dépôt contenant déjà la phase 1 :

```bash
cd ~/projet-6nlg/network-config-audit
source .venv/bin/activate
unzip /mnt/c/Users/LENOVO/Downloads/audit_cisco_ios_phase2_cis15_6nlg.zip
PYTHONPATH=parsers:.:scripts python3 -m unittest discover \
  -s tests -p 'test_*.py' -q
```

Comme cette archive met aussi à jour `audit_engine/benchmark_importer.py`
et son test de phase 1, `unzip` demande confirmation pour ces deux fichiers
existants. Vérifier les éventuelles modifications locales (`git status`) avant
de confirmer leur remplacement. Aucun parseur, normaliseur ou fichier Flask
existant n'est remplacé.

Pour le premier test sur un fichier historique :

```bash
PYTHONPATH=parsers:. python3 scripts/run_cis_ios15_audit.py \
  data/advanced_cases/isp_bgp_base/CE-1.cfg --profile L1 \
  --output reports/cis_ios15_ce1_audit.json
```

**Important :** l'absence de commande produit `UNKNOWN` par défaut. Pour une
exportation dont la complétude est **explicitement confirmée**, ajouter
`--assume-complete`. Les absences deviennent alors `FAIL` sur les contrôles
concernés : ce mode ne doit pas être utilisé sur un extrait incomplet.

Pour inclure le contrôle NTP de niveau 2, employer `--profile L2`. Le profil
L2 inclut les règles L1 du catalogue et l'unique règle L2 du prototype.

## Import du PDF original

L'équipe peut extraire ses candidats localement :

```bash
PYTHONPATH=. python3 -m audit_engine.benchmark_importer \
  /chemin/vers/CIS_Cisco_IOS_15_Benchmark_v4.1.1_ARCHIVE.pdf \
  --product 'Cisco IOS 15' --benchmark-version '4.1.1' \
  --output reports/cis_ios15_candidates.json
```

Ne pas confondre les 89 candidats d'extraction avec 89 contrôles implémentés.
Certaines recommandations exigent une collecte opérationnelle, des exceptions
ou une vérification humaine. Les règles et corrections doivent être confirmées
sur le modèle et la version précise du routeur.

## Limites connues et suite

1. Sous-ensemble réduit : six règles, dont cinq L1 et une L2.
2. Analyse statique seulement : pas d'état SSH/NTP/AAA effectif ni d'impact
   sur le réseau.
3. Aucune lecture des secrets ; seules des informations déclaratives et des
   références de ligne sont exportées.
4. L'intégration Flask et les rapports HTML de conformité restent à réaliser.
5. La source CIS est archivée ; l'applicabilité à IOS 15.9 exact et aux
   plateformes matérielles doit être confirmée avant une conclusion normative.
