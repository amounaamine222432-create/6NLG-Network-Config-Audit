# 6NLG — Adaptateur Juniper IR v2.2 : routage avancé et SRX `display set`

## Objectif et périmètre

Ce correctif complète l'existant ; **il ne remplace ni le parseur Cisco,
ni les convertisseurs IR v1/v2, ni le serveur Flask**.

| Entrée | Bibliothèque de parsing importée | Adaptateur de normalisation |
|---|---|---|
| Junos `show configuration` à accolades | `ciscoconfparse2==0.9.18` | `juniper_ir_adapter.py`, `policy_ir_v2.py`, `juniper_features_ir_v2.py` |
| Junos `show configuration \| display set` | `clijson==0.6.1` | Les **mêmes** normaliseurs après projection de l'AST externe |
| SRX public `config.md` (extrait de commandes `set`) | `clijson==0.6.1` | Même IR, avec avertissement explicite « extrait Markdown » |

`normalizers/junos_tree_loader.py` route les deux syntaxes vers le parseur
tiers adapté. Il présente ensuite aux normaliseurs le même contrat de nœud
`text/parent/children`. Il ne constitue pas un nouveau parseur syntaxique.

La prise en charge `display set` est **partielle et expérimentale** : l'arbre
renvoyé par clijson est une représentation des déclarations, pas une validation
de la grammaire, de l'applicabilité à la plateforme ou de l'état opérationnel.
Les commandes `delete` / `deactivate` et les fichiers `set` mélangés à du texte
non commenté sont volontairement refusés. Les fichiers Markdown explicites
ne sont pas considérés comme des sauvegardes exhaustives de routeurs.

## Éléments normalisés en plus

- **BGP** : `hold-time` (groupe et voisin), `remove-private`, `as-override`,
  `advertise-peer-as`, présence de clé d'authentification **sans valeur**, BFD
  voisin et options de groupes déjà introduites en v2.1.
- **OSPF** : références de politiques `import/export`, aires `stub` / `nssa`,
  `no-summaries`, interfaces `metric`, `priority`, `hello-interval`,
  `dead-interval`, `interface-type`, BFD et authentification masquée.
- **VRF** : `instance-type`, interfaces associées, `vrf-target`,
  `route-distinguisher`, liste des protocoles configurés ; distinction
  maintenue entre VRF Junos et modes non-VRF.
- **SRX** : zones de sécurité, services/protocoles entrants configurés,
  associations d'interfaces, règles entre zones (`match` + action
  `permit/deny/reject`), NAT source vers interface, protections `screen`
  (`icmp`, `ip`, `tcp syn-flood`).

**Aucun audit d'efficacité ni analyse d'état réel n'est effectué**. Une règle
`permit` configurée est rapportée comme telle ; son effet réel sur le trafic
n'est pas conclu. Les noms d'utilisateurs et descriptions libres ne sont pas
exportés. Une configuration contenant des inconnues demeure `partial`.

## Installation dans le dépôt WSL existant

Toutes les commandes suivantes sont lancées à la racine :

```bash
cd ~/projet-6nlg/network-config-audit
source .venv/bin/activate

# SAUVEGARDER D'ABORD les fichiers existants ou travailler sur une branche Git.
git status --short
git switch -c feature/juniper-ir-v22-set-srx

# Extraire le ZIP obtenu (adapter son nom et son emplacement).
unzip -o '/mnt/c/Users/LENOVO/Downloads/6NLG_IR_V2_2_JUNOS_SET_SRX.zip' -d .

python3 -m pip install -r requirements-juniper.txt
```

Ne pas exécuter `git switch -c` si la branche est déjà créée. Si le dépôt
contient des modifications non commitées, les sauvegarder avant `unzip -o`.
Le ZIP ne doit pas être extrait dans `~/` : il est conçu pour la racine du
**projet existant**.

## Tests

```bash
python3 -m unittest discover -s tests -p 'test_juniper_ir_adapter.py' -v
python3 -m unittest discover -s tests -p 'test_policy_ir_v2.py' -v
python3 -m unittest discover -s tests -p 'test_juniper_features_ir_v2.py' -v
python3 -m unittest discover -s tests -p 'test_junos_set_srx_v22.py' -v

# Puis régression globale Cisco + Juniper :
PYTHONPATH=parsers:. python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Environnement de développement du correctif : **30 tests Juniper réussis**
sur Python 3.12, dont 7 nouveaux tests `display set` / sécurité.
La validation globale Cisco + Juniper devra être rejouée **sur le WSL du
projet complet** avant de fusionner la branche.

## Évaluations du corpus externe

```bash
python3 scripts/evaluate_ir_v2_policies.py \
  --junos ../juniper_sources/batfish-lab-validation/snapshots/junos_evpn_type5/source/configs \
          ../juniper_sources/junosphere \
  --schema schemas/network_device_ir_v2.schema.json \
  --output-dir reports/ir_v2_2/juniper \
  --json-summary reports/validation_ir_v2_2_juniper.json \
  --strict-schema

# SRX : chemin vers le fichier .md du dépôt public déjà cloné.
python3 scripts/evaluate_ir_v2_policies.py \
  --junos ../juniper_sources/juniper-srx-config/srx110h-va/config.md \
  --schema schemas/network_device_ir_v2.schema.json \
  --output-dir reports/ir_v2_2/srx \
  --json-summary reports/validation_ir_v2_2_srx.json \
  --strict-schema

# Exemple autonome et reproductible :
python3 scripts/evaluate_ir_v2_policies.py \
  --junos samples/juniper_srx_display_set_demo.cfg \
  --schema schemas/network_device_ir_v2.schema.json \
  --output-dir reports/ir_v2_2/demo \
  --json-summary reports/validation_ir_v2_2_demo.json \
  --strict-schema
```

Résultats reproduits au développement : **24/24** Juniper initiales,
**3/3** holdout additionnels, **1/1** fichier SRX Markdown,
**1/1** exemple synthétique `display set`, tous sans erreur de schéma.
**Tous sont `schema_valid_partial`** : « JSON valide » ne signifie ni
« couverture totale », ni « configuration opérationnellement correcte ».

Sur les 24 originaux, les feuilles *extensions v2* reconnues dans
`routing-instances` passent de **46 à 83** ; restent **18** non reconnues dans
cette section. Ces chiffres sont indépendants de la couverture IR v1.
Sur le seul extrait SRX, **21** feuilles de la section `security` sont
reconnues par l'extension v2 et **8** restent non modélisées. Les exemples
SRX contiennent des valeurs de substitution et ne prouvent pas une
configuration réelle déployée.

## Points à traiter ensuite

1. Améliorer la couverture effective des feuilles `protocols`, `interfaces`
   et `routing-options` (en contrôlant les inconnues par famille) ; certains
   formats avancés BGP/OSPF ne sont validés pour le moment que par des
   tests synthétiques ciblés.
2. Étendre SRX à davantage de règles NAT, firewall et interfaces avec
   tests provenant de **plusieurs sources indépendantes**.
3. Réconcilier les compteurs IR v1 et IR v2 **sans double comptage** ;
   comparer les champs sur des configurations réelles annotées.
4. Intégrer le choix Cisco/Juniper au service Flask et à ses vues HTML,
   avec mise en évidence de la couverture et des limites.

### Sources

- [Batfish lab-validation](https://github.com/batfish/lab-validation)
- [Junosphere](https://github.com/02strich/junosphere)
- [Juniper SRX examples](https://github.com/flightlesstux/juniper-srx-config)
- [CiscoConfParse2](https://github.com/mpenning/ciscoconfparse2)
- [clijson / network-cli-parser](https://github.com/shadymagdy/network-cli-parser)
- [Documentation Juniper display set](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-pipe-display-set.html)
