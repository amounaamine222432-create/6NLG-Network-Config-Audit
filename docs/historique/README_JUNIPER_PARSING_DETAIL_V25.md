# 6NLG / NetAudit — Correctif V2.5 : parsing Juniper détaillé

## Pourquoi ce correctif ?

L'onglet **Parsing JSON** de Cisco fournissait les interfaces, adresses,
protocoles, routes et détails associés. L'export Juniper se limitait à des
compteurs et des listes de noms, même si l'IR v2 contenait davantage
d'informations. Cette asymétrie empêchait de distinguer les données réellement
**extraites par le parseur** de celles **transformées par la normalisation**.

Cette version complète l'inventaire Juniper directement depuis l'arbre de
`ciscoconfparse2` (configurations hiérarchiques) ou de `clijson` (`display set`).
L'export de parsing **n'est pas une copie de l'IR**.

## Nouveaux champs du parsing Juniper

| Rubrique | Informations extraites |
| --- | --- |
| Système | `hostname`, `router_id`, AS global et présence du service SSH |
| Interfaces | Interface physique et logique, unité, IPv4/IPv6, famille, VLAN, MTU, état `disable` configuré |
| Routes | Préfixe, prochain saut, préférence Junos, route globale ou dans une VRF |
| OSPF | Aires, interfaces, métriques, mode passif, politiques d'import/export |
| BGP | Groupes, ASN local/distant, voisins, familles, politiques d'import/export, présence d'authentification |
| VRF | Type d'instance, interfaces, RD, target, BGP et OSPF propres à l'instance |
| Politique de routage | Policy-statements, termes, conditions, actions, prefix-lists, community sets (comptage) |
| Sécurité SRX | Zones, interfaces de zone, services entrants, politiques entre zones et règles NAT source |
| Filtres Junos | `firewall family inet/inet6 filter`, termes, ports, protocoles et actions |
| Autres protocoles | Présence et interfaces pour IS-IS, MPLS, LDP, RSVP, EVPN, LLDP et STP |

Les formats Cisco et Juniper peuvent maintenant être **comparés en richesse
d'inventaire**, sans supprimer leurs différences syntaxiques : par exemple,
une aire OSPF Junos n'est pas un sélecteur `network` Cisco, et une politique
de zone SRX n'est pas une ACL IOS.

### Confidentialité et limites

- L'export n'envoie jamais de mots de passe, hachages, clés, descriptions,
  commandes brutes ou champs non répertoriés. Le JSON est construit avec une
  **liste blanche**, dont les adresses et identifiants sont validés.
- Le champ `source_line` est `null` : les bibliothèques AST ne garantissent
  pas la correspondance avec une ligne physique de la configuration.
- Une directive peut être détectée par le parseur tout en demeurant
  **non modélisée** dans l'IR. Le statut `schema_valid_partial` reste donc
  possible et n'est pas une erreur de chargement.
- Le rapport n'atteste ni l'état opérationnel d'un protocole, ni la
  sécurité ou la conformité réelle du routeur.

## Installation dans WSL Ubuntu

**Prérequis :** votre projet contient déjà l'interface Flask Cisco+Juniper,
les normaliseurs Juniper IR v2.4 et les dépendances installées. Cette archive
est un **correctif**, pas un projet autonome.

Copier le ZIP téléchargé dans `C:\Users\LENOVO\Downloads`, puis lancer :

```bash
cd ~/projet-6nlg/network-config-audit
source .venv/bin/activate

mkdir -p backups/before_juniper_parsing_v25
cp -a webapp/juniper_adapter.py backups/before_juniper_parsing_v25/
cp -a webapp/static/js/app.js backups/before_juniper_parsing_v25/

unzip -o \
  '/mnt/c/Users/LENOVO/Downloads/6NLG_Juniper_Parsing_Detail_V25.zip' \
  -d .
```

Le ZIP crée `webapp/juniper_parsed_preview.py` et met à jour :

- `webapp/juniper_adapter.py` : utilise le parsing détaillé, tout en
  conservant la normalisation IR déjà en place ;
- `webapp/static/js/app.js` : explique correctement la vue de parsing ;
- `webapp/tests/test_webapp_juniper_parsing_v25.py` et quatre fixtures de test ;
- cette notice.

**Attention :** si vous avez modifié localement l'adaptateur ou le JS,
comparez-les à leur sauvegarde après installation, avant de poursuivre.

## Vérification

```bash
cd ~/projet-6nlg/network-config-audit
source .venv/bin/activate

PYTHONPATH=parsers:. python3 -m unittest discover \
  -s webapp/tests -p 'test_*.py' -v

PYTHONPATH=parsers:. python3 -m webapp
```

Ouvrir : <http://127.0.0.1:5050>

Sélectionner **Juniper Junos / SRX**, importer les quatre fichiers de
`tests/fixtures_juniper_v24/`, puis regarder **Vue complète** et
**Parsing JSON**. La **Normalisation IR** et le **Rapport HTML** restent
des livrables distincts.

### Vérifications réalisées lors de la préparation

- **25 tests Flask** : réussis, dont 5 nouveaux tests du parsing détaillé.
- **93 tests du cœur Cisco** : réussis.
- **43 tests du cœur Juniper** : réussis, dont 15 ignorés suivant
  leurs prérequis de corpus.
- Parsing détaillé de **6 fichiers Batfish**, **18 configurations Junosphere
  non vides** et **1 configuration SRX** : aucun chargement en échec.
  Trois fichiers `CTS0.conf` vides de Junosphere sont explicitement exclus.

Les quatre configurations livrées sont des **fixtures synthétiques de
validation**. Pour une validation scientifique de la couverture et des
fonctionnalités, conserver aussi les corpus publics indépendants et comparer
chaque champ normalisé à sa source de configuration.
