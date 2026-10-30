# Phase 6 — Section indépendante d'audit CIS dans Flask

## Principe

Le module **Security Audit Center**, accessible depuis la barre latérale de
NetAudit, complète l'application existante sans modifier les résultats des
modules *Parsing*, *Normalisation IR* et *Rapport HTML*.

La route `POST /api/cis/audit` travaille exclusivement sur Cisco IOS :

1. Fichier `.cfg`/`.txt` analysé en mémoire, 1 Mio maximum, avec le même contrôle
   de compatibilité Cisco IOS que l'application actuelle.
2. `parse_cisco_ios` : reconnaissance des déclarations IOS.
3. `normalize_cisco_ios` : IR structuré existant.
4. `audit_cis_ios15` : 39 contrôles sélectionnés du benchmark CIS IOS 15
   v4.1.1, dans `benchmarks/rules/cisco_ios/cis_ios15_v4.1.1_phase5_lab.json`.
5. Rapport CIS indépendant : regroupement en trois domaines, verdicts,
   éléments probants, remédiations, export JSON et **nouveau HTML technique**.

Les chaînes brutes de configuration ne sont pas conservées. Les exports sont
réservés à la session qui a lancé l'audit et expirent au bout de 30 minutes.

## Installer la mise à jour

À partir de `~/projet-6nlg/network-config-audit`, **après avoir sauvegardé les
fichiers éventuellement modifiés**, extraire l'archive de Phase 6 à la racine :

```bash
unzip -l /mnt/c/Users/LENOVO/Downloads/audit_cisco_ios_phase6_flask_6nlg.zip
unzip /mnt/c/Users/LENOVO/Downloads/audit_cisco_ios_phase6_flask_6nlg.zip
source .venv/bin/activate
PYTHONPATH=parsers:.:scripts python3 -m unittest webapp.tests.test_webapp webapp.tests.test_webapp_cis_phase6 -v
PYTHONPATH=parsers:.:scripts python3 -m webapp
```

Se rendre sur `http://127.0.0.1:5050/#cis-audit` puis, pour un essai :

| Cas | Fichier | Profil | Complète | Interface externe | Verdicts attendus |
| --- | --- | --- | --- | --- | --- |
| Conforme | `data/cis_phase5/router_compliant.cfg` | L2 | Oui | `GigabitEthernet0/0` | 36 PASS, 0 FAIL, 3 N/A |
| Non conforme | `data/cis_phase5/router_non_compliant.cfg` | L2 | Oui | `GigabitEthernet0/0` | 2 PASS, 33 FAIL, 4 N/A |
| Incomplet | `data/cis_phase5/router_partial.cfg` | L2 | Non | *(vide)* | 1 PASS, 38 UNKNOWN |

Le formulaire CIS utilise son **propre** champ de fichier, son profil et son
option de complétude ; il ne dépend pas des résultats d'une analyse précédente
dans l'onglet « Importer & analyser ».

## Références et précautions

- `PASS` : conformité *statique* au contrôle implémenté.
- `FAIL` : déclaration explicitement incorrecte ou absence déduite d'une
  configuration **déclarée complète**.
- `UNKNOWN` : absence de preuve suffisante ; jamais convertie en PASS.
- `NOT_APPLICABLE` : contrôle non pertinent pour le cas présenté.
- `NOT_SELECTED` : contrôle hors profil L1.

Le ratio « PASS parmi les contrôles conclusifs » ne porte **que** sur
`PASS + FAIL`. Ce n'est **pas** un pourcentage de conformité au benchmark entier.
Les contrôles reposent sur la configuration déclarée et ne vérifient pas la
disponibilité opérationnelle du routage, des ACL ou de l'authentification.

L'interface ne réalise aucun accès SSH ; le collecteur CLI en lecture seule
`scripts/collect_ios_show.py` reste une étape indépendante.

### Fichiers ajoutés

- `webapp/cis_dashboard.py` : regroupement et indicateurs de présentation.
- `webapp/templates/report_cis_ios.html` : rapport HTML CIS technique indépendant.
- `webapp/static/css/cis_audit.css` : styles isolés de la nouvelle section.
- `webapp/static/js/cis_audit.js` : formulaire, filtres et résultats CIS.
- `webapp/tests/test_webapp_cis_phase6.py` : tests d'intégration et de sécurité.

### Fichiers modifiés

- `webapp/app.py` : nouvelles routes CIS et stockage de rapport séparé.
- `webapp/templates/index.html` : navigation et panneau de sécurité CIS.

L'export CIS est un **prototype d'audit non certifié**, et non l'ensemble du
benchmark CIS IOS 15 v4.1.1.
