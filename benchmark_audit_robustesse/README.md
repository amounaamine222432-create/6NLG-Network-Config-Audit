# 6NLG — Benchmark de robustesse du moteur CIS V68

Tests adversariaux ciblés : **20 configurations IOS 15**, **33 assertions**,
avec statuts attendus et justifications fixés avant le lancement du moteur.

## Exécution sous WSL, à la racine du dépôt

```bash
export PYTHONPATH="$PWD:$PWD/parsers:$PWD/scripts"
python3 benchmark_audit_robustesse/execute.py --project .
python3 benchmark_audit_cis_117/run_117.py --project .
python3 -m unittest tests.test_cis15_corrections_v68 tests.test_cis15_engine tests.test_cis15_phase4 -v
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Résultats : `benchmark_audit_robustesse/output/RAPPORT_ROBUSTESSE.html`,
`results.csv`, `results.json`, `summary.json` et 20 `.cfg` individuels.

## Observations sur la copie locale

- 20 configurations / 33 assertions : **33 correspondances et 0 divergence**.
- Benchmark synthétique antérieur : 117/117 correspondances.
- Régressions ciblées (23 tests) : OK.
- La suite complète a été démontrée à **195/195 sur le WSL utilisateur**, d'après
  le journal fourni précédemment. Sur la copie locale, les fixtures `data/`
  sont absentes ; relancer sur le WSL pour la validation finale.
- **Aucune correction du moteur** n'a été produite : pas d'anomalie établie.

Les oracles sont des appréciations synthétiques rédigées manuellement et
doivent encore être confirmés indépendamment par une personne connaissant
la configuration Cisco IOS et les exigences officielles CIS. Des tests
unitaires réussis ne prouvent pas l'absence de faux positifs/faux négatifs
sur toutes les configurations réelles.

Limites restantes : variantes IOS non représentées, ambiguïtés de commande,
preuves opérationnelles (`show`) indisponibles, dépendances à la topologie,
ACL complexes, comportement effectif du trafic et représentativité d'un
échantillon de routeurs de production. Les règles ne doivent pas être
ajustées pour simplement maximiser le score observé.
