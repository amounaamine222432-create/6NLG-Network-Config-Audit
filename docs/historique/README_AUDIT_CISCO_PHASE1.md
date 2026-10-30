# 6NLG — Démarrage du moteur d'audit Cisco IOS (phase 1)

Ce lot **ajoute** des fichiers. Il ne remplace ni le parseur, ni le normaliseur,
ni les routes Flask existantes. Il ne se connecte à aucun routeur et ne modifie
aucune configuration.

## 1. Prérequis et extraction d'un benchmark

Télécharger légalement un benchmark correspondant exactement à la famille et
à la version de Cisco IOS visée : https://www.cisecurity.org/benchmark/cisco .
Un PDF de benchmark n'est **pas** fourni dans ce lot.

```bash
cd ~/projet-6nlg/network-config-audit
source .venv/bin/activate
python3 -m pip install -r requirements-audit.txt
PYTHONPATH=. python3 -m audit_engine.benchmark_importer \
  /chemin/vers/benchmark-cisco-ios.pdf \
  --product 'Cisco IOS 16' \
  --benchmark-version '2.0.0' \
  --output reports/cisco_ios_benchmark_candidats.json
```

Adapter `--product` et `--benchmark-version` au **document réellement
importé**. Le script ne détecte pas automatiquement la version du benchmark.
La sortie contient les intitulés, extraits Audit/Remediation et pages, mais
chaque entrée reste `review_required` : aucun résultat de conformité n'est
calculé à partir de ces candidats.

Limites de l'extracteur : PDF textuel uniquement (pas d'OCR), extraction par
titres numérotés, possible confusion en cas de mise en page complexe. Vérifier
le nombre, le contenu et les références de chaque contrôle dans le PDF source.
Respecter également les droits de modification et de redistribution du document.

## 2. Démonstration du premier contrôle hors benchmark

Le moteur sait évaluer une règle **illustrative** sur le vrai champ IR
`management.http_enabled`, présent dans `normalizers/cisco_normalizer.py`.
La règle `IOS-DEMO-HTTP-001` n'est **pas** attribuée à CIS : son `benchmark_ref`
est null et son statut est `demo`. Le moteur ne l'exécute qu'avec une
autorisation explicite du démonstrateur.

```bash
PYTHONPATH=parsers:. python3 scripts/demo_audit_ios.py \
  R-6NLG-GLOBAL-TEST-01.cfg
```

Pour le fichier disponible dans votre dépôt, adapter le chemin. `PASS` indique
seulement que le champ IR correspond à la valeur attendue ; ce n'est pas une
certification de sécurité ni une observation de l'état opérationnel.

## 3. Tests

```bash
PYTHONPATH=parsers:. python3 -m unittest \
  tests.test_benchmark_importer_6nlg tests.test_rule_engine_6nlg -v
```

S'il n'y a pas de `tests/__init__.py`, employer :

```bash
PYTHONPATH=parsers:. python3 -m unittest discover \
  -s tests -p 'test_*6nlg.py' -v
```

## 4. Prochaine étape (phase 2)

1. Importer le benchmark réellement choisi.
2. Examiner quelques recommandations candidates et les associer à l'IR.
3. Enregistrer des règles approuvées avec référence et applicabilité vérifiées.
4. Étendre les opérateurs et les statuts, puis intégrer l'évaluation à Flask.

Les configurations IOS 15.9 utilisées dans les essais nécessitent un choix
explicite de benchmark applicable : ne pas les déclarer conformes à un
benchmark IOS 16 ou IOS 17 sans vérification des différences de version.
