# 6NLG — renforcement transversal des 39 contrôles CIS IOS 15

## Installation

Ce correctif s'applique à la racine du projet `network-config-audit`.
Conserver une copie de la version en place avant extraction ; n'écraser que
les fichiers répertoriés dans l'archive. Ne jamais extraire dans `~`.

## Contenu de la livraison

- `audit_engine/cis15_phase5_checks.py` : ACL VTY plus conservatrices ; une
  permission `0.0.0.0 255.255.255.255` est aussi large que `any` ; un format
  source inconnu donne `UNKNOWN` plutôt qu'un `PASS` infondé.
- `audit_engine/cis15_engine.py` : métadonnées de couverture des 39 règles,
  périmètre statique et indicateur de revue manuelle par verdict.
- `webapp/cis_dashboard.py` : qualification d'impact explicite des 39
  contrôles ; distinction entre directive, repère de bloc et absence d'ancrage.
- `webapp/templates/report_cis_ios.html` : visibilité de cette distinction.
- `webapp/pdf_exports.py` : même distinction dans les rapports PDF.
- `tests/test_cis39_regression.py` : régression 39 × 3 scénarios + contexte WAN,
  complétude et ACL wildcard.

## Vérification depuis la racine du projet

```bash
PYTHONPATH=.:parsers:final_validation_6nlg python3 -m unittest tests.test_cis39_regression -v
python3 validation_reference_cis_39/run_validation.py .
```

Résultat observé sur le jeu local : 4 tests unitaires OK, 117/117 attentes
CIS de référence, 0 anomalie, sur trois configurations de laboratoire.

## Important : portée de la validation

La couverture de 39/39 signifie que les 39 identifiants possèdent un contrôle
implémenté et ont un attendu vérifié sur chacun des 3 scénarios. Ce chiffre
**ne prouve pas** la justesse pour toutes les syntaxes Cisco, toutes les
topologies et tous les contre-exemples possibles. Ce travail n'est pas une
certification CIS. Les contrôles WAN exigent une désignation explicite des
interfaces externes ; l'exactitude opérationnelle (commandes SHOW) reste à
vérifier sur les routeurs autorisés. Les preuves affichées sont expurgées.

## Pistes de validation restantes

Élargir le jeu aux cas négatifs indépendants pour chacun des 39 contrôles,
aux ACL complexes avec séquence/ports/objets, aux variantes IOS 15 et à
des équipements réels autorisés. Conserver UNKNOWN lorsque le parseur ou
l'IR ne peut attester un comportement effectif.
