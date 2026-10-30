# Validation expérimentale du moteur V68 — CIS IOS 15

## Exécution depuis la racine du dépôt

```bash
export PYTHONPATH="$PWD:$PWD/parsers:$PWD/scripts"
python3 benchmark_audit_cis_117/run_117.py --project .
python3 benchmark_audit_cis_117/compare_html_cis.py --project .
python3 -m unittest tests.test_cis15_corrections_v68 -v
python3 -m unittest discover -s tests -p 'test_*.py'
```

Les 117 configurations indépendantes les unes des autres sont écrites dans
`benchmark_audit_cis_117/run_output/configs/` ; les résultats sont exportés
vers `run_output/results.csv`, `results.json`, `summary.json` et `RESULTATS_117.html`.

`output/COMPARAISON_CIS_VS_HTML_EXISTANTS.html` compare aussi les deux audits
préexistants au catalogue **local** de laboratoire.

## Méthode et limites importantes

- 39 contrôles CIS du catalogue local, 3 configurations ciblées par contrôle,
  soit 117 tests de décision. Chaque oracle PASS, FAIL ou UNKNOWN est fixé dans
  la définition des cas avant l'appel au moteur, et non généré depuis sa sortie.
- Les configurations sont **synthétiques et ciblées** ; beaucoup se limitent à
  quelques commandes IOS. Elles ne remplacent ni un test d'intégration sur une
  configuration complète ni la validation par un spécialiste du benchmark CIS.
- Le cas `no_tunnel_interfaces` avec aucune interface Tunnel est évalué PASS
  uniquement si la configuration est déclarée complète ; dans une extraction
  partielle, l'absence de preuve doit rester UNKNOWN.
- Le marqueur UNKNOWN représente ici une extraction partielle minimale ; cela
  n'épuise pas les causes d'incertitude (commandes opaques, conflits, show absents).
- Les résultats ne constituent **pas** une certification CIS officielle.
  Le PDF source du benchmark CIS doit être vérifié contrôle par contrôle avant
  d'employer le mot conformité et avant de publier un score de référence.
- Le taux de correspondance et les F1 calculés dans `summary.json` concernent
  **uniquement ces 117 cas synthétiques** ; ne pas les généraliser.

## Résultats exécutés sur la copie locale

117/117 correspondances ; 0 écart confirmé nécessitant une modification du moteur.
23 tests ciblés du moteur (`test_cis15_corrections_v68`, `test_cis15_engine`,
`test_cis15_phase4`) ont réussi. Le complément parsing/IR de 30 configurations
a réussi 158 assertions / 158. La suite complète de 151 tests sur cette copie
**n'a pas pu réussir** : 22 erreurs/échecs liés à l'absence de fichiers de
fixtures `data/cis_phase5/` et `data/advanced_cases/` dans la copie accessible.
Relancer la suite complète sur le dépôt WSL contenant ces fixtures.

## Détection d'anomalies supplémentaires

Ajouter les scénarios adversariaux et les configurations réelles à cette matrice,
faire contrôler indépendamment leur statut attendu, puis signaler tout écart
avec son `.cfg`, son `expected`, son `actual`, ses `evidence` et son JSON IR.
Ne modifier le moteur que lorsqu'un défaut a été démontré de cette façon.
