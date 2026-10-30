# 6NLG — Prototype IR v2 : politiques de routage Cisco / Juniper

## Objectif et périmètre

Cette extension ne modifie **aucun fichier Cisco existant**, ne remplace
pas le schéma IR v1 et n'introduit pas un parseur Junos fait maison.
Le parsing hiérarchique Juniper repose toujours sur `ciscoconfparse2`.

L'IR v2 reprend tous les champs v1 et ajoute aux `policies` :

- `route_policies[]` : une politique et ses termes dans l'ordre défini ;
- `community_sets[]` : noms et communautés déclarées ;
- `vendor_semantics` : `junos` ou `cisco_ios`, pour éviter les assimilations
  dangereuses entre termes Junos et route-maps Cisco ;
- `unmodeled_condition_count` et `unmodeled_action_count` : inconnues visibles.

## Installer dans le projet existant (WSL)

Télécharger `6NLG_IR_V2_Politiques_Pilote.zip` dans `Downloads`, puis :

```bash
cd ~/projet-6nlg/network-config-audit
source .venv/bin/activate
unzip -n /mnt/c/Users/LENOVO/Downloads/6NLG_IR_V2_Politiques_Pilote.zip -d .
```

L'archive ajoute ces fichiers **sans écraser les anciens** :

```text
schemas/network_device_ir_v2.schema.json
normalizers/policy_ir_v2.py
scripts/evaluate_ir_v2_policies.py
tests/test_policy_ir_v2.py
README_IR_V2_POLITIQUES_6NLG.md
reports/NOTE_RESULTATS_IR_V2.md
reports/validation_policy_ir_v2.json
reports/ir_v2_examples/*.ir_v2.json
```

## Validation Juniper

```bash
python3 scripts/evaluate_ir_v2_policies.py \
  --junos \
    ../juniper_sources/batfish-lab-validation/snapshots/junos_evpn_type5/source/configs \
    ../juniper_sources/junosphere \
  --schema schemas/network_device_ir_v2.schema.json \
  --output-dir reports/ir_v2/juniper \
  --json-summary reports/validation_ir_v2_juniper.json \
  --strict-schema
```

## Validation Cisco et Juniper simultanée

Le corpus synthétique Cisco déjà présent dans votre projet est ici pris en exemple.
Le script réutilise directement le parseur et le normaliseur Cisco actuels.

```bash
python3 scripts/evaluate_ir_v2_policies.py \
  --junos \
    ../juniper_sources/batfish-lab-validation/snapshots/junos_evpn_type5/source/configs \
    ../juniper_sources/junosphere \
  --cisco data/holdout_synthetique_v66 \
  --schema schemas/network_device_ir_v2.schema.json \
  --output-dir reports/ir_v2/comparaison \
  --json-summary reports/validation_ir_v2_multiconstructeur.json \
  --strict-schema
```

Si les trois fichiers Cisco ne sont pas à cet emplacement, remplacez le
chemin de `--cisco` par votre répertoire réel.

## Tests de régression

```bash
python3 -m unittest discover -s tests -p 'test_policy_ir_v2.py' -v
python3 -m unittest discover -s tests -p 'test_juniper_ir_adapter.py' -v
```

## Évaluation réalisée

- 24 fichiers Junos (6 Batfish + 18 Junosphere) : schéma v2 validé.
- 3 fichiers Cisco synthétiques : schéma v2 validé après conversion d'IR v1.
- 71 objets route-policy dans les 27 fichiers, 122 termes ; 25 définitions
  de communautés Junos.
- Politiques Junos : **264 feuilles reconnues / 303**, 39 non encore adaptées.

Les compteurs v1 (notamment les 719 feuilles non normalisées) sont
**conservés comme ligne de base** dans le diagnostic. Les nouveaux compteurs
`policy_v2_leaf_count_recognized` et `policy_v2_leaf_count_unmodeled`
mesurent uniquement l'extension politiques v2 et ne doivent pas être additionnés
aux totaux v1.

**Important :** ce résultat démontre que la nouvelle structure sérialise ces
configurations et qu'un sous-ensemble syntaxique documenté est traduit. Ce
n'est **pas** une preuve de l'équivalence opérationnelle des politiques ni de
leur sécurité. Les 24 fichiers Junos ont servi à concevoir et à tester le
prototype ; un nouveau jeu indépendant et une vérification humaine des champs
sont nécessaires avant d'annoncer une validation scientifique externe.

## Références constructeur (sémantique)

- https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/concept/policy-configuring-actions-in-routing-policy-terms.html
- https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/concept/policy-configuring-match-conditions-in-routing-policy-terms.html
- https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/concept/policy-configuring-route-lists-for-use-in-routing-policy-match-conditions.html
- https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/community-edit-policy-options.html
