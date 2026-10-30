# 6NLG — Correctif IR v2.3 : couverture SRX / PPPoE / interfaces

## Portée

Ce correctif s'ajoute **au dépôt `network-config-audit` existant**. Il réutilise
`ciscoconfparse2` pour Junos à accolades et `clijson` pour le format `display set` ;
les fichiers du parseur Cisco et ceux de Flask ne sont pas modifiés.

Il ne s'agit ni d'un moteur d'audit de sécurité, ni d'une validation de l'état
réel du routeur. Les champs indiquent ce qui est **configuré** dans les fichiers.
La valeur `schema_valid_partial` reste correcte tant que le document ne permet
pas de certifier l'exhaustivité ni l'applicabilité de sa configuration.

## Correctifs ciblés

| Famille | Directives intégrées dans l'extension IR v2.3 |
|---|---|
| Interfaces | VLAN `vlan-tagging` / `vlan-id`, encapsulation PPP, profil VDSL, DHCP, adresses IPv4, IPv4 négociée, `family inet`, options PPPoE et `traceoptions` |
| Authentification PPP | Détection de PAP, de son nom d'utilisateur et de son mot de passe **sans publier leurs valeurs** |
| Groupes d'interfaces | `interface-range`, membres, association aux VLAN |
| Sécurité SRX | Services et protocoles `host-inbound-traffic` **par interface de zone** ; TCP MSS configuré |
| Routage statique | `next-hop` IP ou interface et `metric`, distinct de la distance administrative Cisco |
| Protocoles | Déclaration `protocols stp` |

La prise en charge de BGP, OSPF, VRF, EVPN, politiques et règles de sécurité
déjà disponible en v2.2 est conservée. Les commandes non reconnues ou comportant
des paramètres invalides restent dans les compteurs « non normalisées ».

### Résultats observés

Sur **un extrait Markdown de configuration SRX public**, et exclusivement pour
les feuilles des **extensions fonctionnelles Junos v2**, les résultats sont :

| Section | Reconnues v2.2 | Restantes v2.2 | Reconnues v2.3 | Restantes v2.3 |
|---|---:|---:|---:|---:|
| interfaces | 6 | 19 | 25 | 0 |
| routing-options | 0 | 2 | 2 | 0 |
| protocols | 0 | 1 | 1 | 0 |
| security | 21 | 8 | 29 | 0 |
| **Total** | **27** | **30** | **57** | **0** |

Cela veut dire **57/57 feuilles reconnues dans cet exemple SRX**, pas que
« Junos est normalisé à 100 % », ni que les données de l'IR v1 et v2 peuvent
être additionnées sans double comptage. Le fichier SRX comporte des espaces
réservés et ne doit pas être présenté comme une sauvegarde réelle complète.

Sur les **24 configurations Batfish + Junosphere**, toutes les structures IR v2
restent valides (statut `schema_valid_partial`) ; les feuilles d'extensions
`interfaces` reconnues passent de 66 à 165, et celles non modélisées de 175 à
76. Il reste, entre autres, 143 feuilles `protocols`, 58 `routing-options`
et 18 `routing-instances` non normalisées dans ce corpus. Les trois fichiers
de contrôle supplémentaires et l'exemple local `display set` passent aussi.

## Installer dans WSL (sans recréer le projet)

```bash
cd ~/projet-6nlg/network-config-audit
source .venv/bin/activate
git status --short
```

**Avant d'écraser un fichier**, conserver les changements non commités (commit
ou copie de sauvegarde), puis extraire le ZIP téléchargé **à la racine de ce
projet**, et non dans `~/` :

```bash
unzip -o '/mnt/c/Users/LENOVO/Downloads/6NLG_IR_V2_3_SRX_COUVERTURE.zip' -d .
python3 -m pip install -r requirements-juniper.txt
```

Ne pas réécrire les normaliseurs Cisco ni les pages Flask : ils sont extérieurs
à cette étape. Les fichiers JSON des résultats sont des résumés sans commandes
brutes et ne remplacent pas une revue de conformité ou de sécurité.

## Tester

```bash
python3 -m unittest discover -s tests -p 'test_juniper_srx_extensions_v23.py' -v

# Régression globale Cisco et Juniper, depuis la racine du dépôt :
PYTHONPATH=parsers:. python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Dans l'environnement de développement de ce correctif : **36/36 tests Juniper
réussis** (dont six nouveaux tests v2.3). Les tests de la suite complète Cisco
et Juniper doivent être relancés dans le dépôt WSL de l'équipe ; ils ne sont
pas attestés ici.

### Évaluer l'extrait SRX

```bash
python3 scripts/evaluate_ir_v2_policies.py \
  --junos ../juniper_sources/juniper-srx-config/srx110h-va/config.md \
  --schema schemas/network_device_ir_v2.schema.json \
  --output-dir reports/ir_v2_3/srx \
  --json-summary reports/validation_ir_v2_3_srx.json \
  --strict-schema
```

### Évaluer les 24 autres configurations Junos

```bash
python3 scripts/evaluate_ir_v2_policies.py \
  --junos ../juniper_sources/batfish-lab-validation/snapshots/junos_evpn_type5/source/configs \
          ../juniper_sources/junosphere \
  --schema schemas/network_device_ir_v2.schema.json \
  --output-dir reports/ir_v2_3/juniper \
  --json-summary reports/validation_ir_v2_3_juniper.json \
  --strict-schema
```

## Limites et prochaine étape

1. `schema_valid_partial` signifie que le JSON respecte le schéma, **pas** que
   les chemins de réseau, les annonces BGP ou les règles SRX fonctionnent.
2. Les valeurs sensibles PAP, noms de services PPPoE et secrets d'authentification
   ne sont pas exposés dans les JSON ; l'IR décrit leur seule présence.
3. Le parseur externe `clijson` fournit un arbre `display set` ; les formes
   invalides ou inconnues ne sont pas inventées par l'adaptateur.
4. Il faut maintenant traiter les familles non couvertes dans les autres
   corpus, construire des oracles attendus champ par champ et tester sur des
   configurations supplémentaires indépendantes avant de lancer l'audit.

### Sources documentaires pour les sémantiques

- [Juniper — PPPoE](https://www.juniper.net/documentation/us/en/software/junos/subscriber-mgmt-access/topics/topic-map/subscriber-access-pppoe.html)
- [Juniper — route `metric`](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/metric-edit-routing-options.html)
- [Juniper — `host-inbound-traffic`](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-zone-configuration.html)
- [Juniper — `interface-range`](https://www.juniper.net/documentation/us/en/software/junos/interfaces-ethernet/topics/topic-map/interface-ranges.html)
- [Corpus Batfish](https://github.com/batfish/lab-validation), [Junosphere](https://github.com/02strich/junosphere), [SRX public](https://github.com/flightlesstux/juniper-srx-config)
