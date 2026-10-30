# Phase 8 — Traçabilité des preuves CIS IOS 15

Cette amélioration est une **surcouche de présentation**, sans modification des 39 règles, des profils L1/L2, des verdicts du moteur ni du parsing/IR existants.

## Chaîne connectée

1. Charger une configuration Cisco IOS classique dans le formulaire CIS de l'application Flask.
2. Le parseur produit les structures Cisco, puis le normaliseur génère l'IR.
3. Le moteur statique CIS évalue les **39 contrôles du sous-ensemble de laboratoire**.
4. `enrich_cis_report(..., ir)` ajoute les explications et les **repères issus de `source.line`** conservés dans l'IR. Aucune donnée secrète brute n'est requise.
5. L'interface et le rapport CIS montrent, pour chaque contrôle : exigence, observation, provenance, analyse, impact, correction, précaution et commande de vérification. Le rapport de parsing et normalisation reste un PDF indépendant.

## Précision de la provenance

- `source_anchors` : objets JSON `{line, element, scope}` avec numéro de ligne **1-based** dans la configuration source.
- `scope="ligne de règle ACL"` : repère exact de l'entrée ACL normalisée.
- `scope="ligne de directive"` : repère direct d'une déclaration AAA, compte, SNMP, Syslog ou serveur NTP présente dans l'IR.
- `scope="début de bloc"` : repère du début de `line vty`, `interface`, `router ospf`, etc. **Ce numéro ne prétend pas identifier la sous-commande fautive**.
- Si aucune ligne fiable n'est présente dans l'IR (ou si l'absence est seulement inférée), aucun repère source n'est inventé.
- Les noms d'ACL et d'interfaces sont repris de l'IR après validation stricte pour personnaliser le texte des commandes `show`. Ces commandes restent **des suggestions en lecture seule, jamais exécutées** par l'application.
- Les valeurs `password`, `secret`, les communautés SNMP et les chaînes de clés ne sont pas transférées dans ces repères.

## Exemples reproductibles

Depuis la racine du dépôt, dans l'environnement Python de l'application :

```bash
PYTHONPATH=parsers:.:scripts python3 -m unittest \
  webapp.tests.test_webapp_cis_phase6 \
  webapp.tests.test_webapp_cis_pipeline_pdf -q

PYTHONPATH=parsers:.:scripts python3 scripts/export_cis_demo_pdf.py \
  data/cis_phase5/router_non_compliant.cfg \
  --profile L2 --assume-complete \
  --external-interface GigabitEthernet0/0 \
  --output-dir output/pdf
```

Les exemples non conformes utilisent les noms observés `MGMT-OPEN` et `WAN-OPEN` dans les commandes `show ip access-lists ...`, ainsi que `GigabitEthernet0/0` pour `show ip interface ...`.

Le fichier de phase 8 livré est un **overlay** sur la phase 7 : décompresser à la racine du projet existant pour remplacer les fichiers indiqués. Il ne contient ni configuration réelle ni secrets.

**Portée :** prototype non certifié CIS ; il couvre les 39 contrôles implémentés, et non l'intégralité du benchmark Cisco IOS 15 v4.1.1. Une configuration partielle reste inconclusive lorsque les preuves manquent.
