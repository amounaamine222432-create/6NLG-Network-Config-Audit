# Benchmark Cisco IOS 15 — 30 configurations / 525 faits

## Résultats mesurés sur le moteur V6.7 corrigé

| Etape | TP | FP | FN | Precision | Rappel | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Parsing | 525 | 0 | 0 | 100 % | 100 % | 100 % |
| Normalisation IR | 525 | 0 | 0 | 100 % | 100 % | 100 % |

Les résultats proviennent d'un **corpus synthétique déterministe**, avec des références générées à partir de paramètres déclaratifs indépendants des sorties des deux composants. Ils ne constituent pas une mesure de fiabilité sur des configurations réelles indépendantes ni une certification du moteur.

## Corpus

- `configs/` : 30 configurations IOS 15, dont 10 OK, 10 FAIL, 5 MIXED, 5 PARTIAL.
- `gold/` : une liste de faits attendus par configuration, issue des spécifications des scénarios, et non du parseur.
- `manifest.json` : catégories et nombre de faits par cas.
- `build_corpus.py` : régénération déterministe du jeu de données.
- `evaluate.py` : lecture des configurations, parsing, IR et comparaison des faits.
- `results/details.json` : comparaisons par cas et par étape, dont preuves manquantes ou inventées.
- `results/summary.json` : TP, FP, FN, précision, rappel et F1.

## Reproduire sur Ubuntu

Copier le dossier `benchmark_30_6nlg` à la racine du projet `network-config-audit`, puis exécuter :

```bash
cd ~/projet-6nlg/network-config-audit
source .venv/bin/activate
python3 benchmark_30_6nlg/evaluate.py --project .
```

Les résultats sont enregistrés dans `benchmark_30_6nlg/results/`.

## Champs effectivement évalués

Hostname, version IOS, IP source routing, AAA, SSH version, interfaces IPv4, routes statiques, timeout console/VTY, transport VTY, méthode login, bannières, niveaux d'accès SNMP, tampon Syslog, destination Syslog et serveur NTP.

Les mesures utilisent une comparaison **multiensemble de faits exacts**. Pour les fonctions non présentes dans ce corpus (BGP, OSPF, EIGRP, ACL détaillées, NAT, DHCP, VLAN, VRF), aucune conclusion quantitative n'est possible. Les configurations partielles ne sont pas traitées comme des configurations complètes.

## Prochaine validation indépendante indispensable

1. Constituer un jeu *holdout* de configurations provenant de sources différentes, avec variantes IOS représentatives, secrets anonymisés et autorisation d'usage.
2. Faire annoter manuellement les faits de référence par deux personnes, arbitrer les désaccords avant de lancer le parseur.
3. Étendre la grille aux fonctionnalités de notre périmètre qui ne sont pas couvertes par les 525 faits.
4. Mesurer par famille et ajouter une métrique à poids élevé pour toute perte de preuve de sécurité.
5. Mesurer séparément la qualité des verdicts PASS/FAIL/UNKNOWN des 39 règles CIS à partir de réponses de référence indépendantes.

**Ne pas présenter ces 100 % comme précision générale du logiciel.** Le bon libellé est : « 100 % de précision et rappel sur un corpus synthétique ciblé de 525 faits ».
