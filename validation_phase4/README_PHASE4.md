# 6NLG — Phase 4 : protocole de validation finale

## Installation sur WSL

Décompresser l'archive depuis la **racine du dépôt** `network-config-audit` (préserver les répertoires).

```bash
cd ~/projet-6nlg/network-config-audit
source .venv/bin/activate
export PYTHONPATH="$PWD:$PWD/parsers"
python scripts/validate_phase4.py
```

Résultats : `validation_phase4/results/phase4_validation.html` et `.json`.
Le programme retourne **0 seulement lorsque les quatre volets sont PASS** ; sinon il retourne 1. Pour obtenir le journal détaillé, lire le champ `log_tail` du JSON. L'absence de Flask ou d'une fixture compte comme défaut de validation et non comme succès.

## Matrice de couverture

| Volet | Critère de validation | Tests |
|---|---|---|
| CIS | Catalogue exact de 39 règles, verdicts attendus, preuves source, absence de secrets | `test_cis*.py`, holdout de 78 verdicts |
| Cohérence | Sous-réseaux, routes, ACL, OSPF, BGP, VLAN, NAT, DHCP et cas incomplets | `test_network_coherence`, `test_network_advanced_v75`, `test_cis_network_phase12` |
| Pipeline | Parsing → IR → CIS + cohérence, six cas, 39 identifiants uniques, compteurs et verdicts | `validation_phase4/fixtures/*.cfg` |
| Interface | Imports, extensions, limites de taille, CSRF, échappement HTML, confidentialité, navigation et rapports | `unittest discover -s webapp/tests` |

Les six configurations sont **synthétiques** et ne doivent jamais être chargées sur un routeur réel. Les comptages CIS sont des *oracles de régression* basés sur la version de référence ; si le moteur change intentionnellement, documenter l'évolution avant de mettre à jour ces valeurs. `UNKNOWN` et `REVIEW` ne doivent pas être convertis silencieusement en `PASS` ou `FAIL`.

## Points à vérifier manuellement avant soutenance

1. Sur Flask, importer une configuration puis vérifier que son contenu est consultable avant l'analyse, sans afficher de secrets en clair dans les rapports.
2. Ouvrir chaque preuve d'une anomalie et vérifier le numéro et la commande source ; contrôler la coloration, l'explication et la correction contextualisée.
3. Exporter les rapports HTML/PDF et le rapport HTML de remédiation ; vérifier les accents, les sauts de page, les références CIS et les commandes proposées.
4. Confirmer l'absence de section « Comparer avant / après » dans le rapport CIS V77.
5. Sur un environnement de test uniquement, essayer fichiers vides, encodages invalides, noms inattendus, grands fichiers, requêtes CSRF invalides, plusieurs imports et descriptions contenant du HTML ; vérifier qu'aucun secret n'apparaît dans les exports.
6. Vérifier les limitations d'une analyse statique : les voisins BGP, les routes récursives et les ACL doivent être corroborés par des commandes `show` ou un test réel avant d'affirmer l'état opérationnel.

## Condition de clôture

La phase 4 est **validée** uniquement avec un `PASS` global sur l'environnement WSL cible, et les vérifications manuelles ci-dessus sont consignées et signées. Un rapport vert sur un sous-ensemble ne constitue pas une validation complète.
