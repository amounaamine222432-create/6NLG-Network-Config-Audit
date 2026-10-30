# Trois configurations Cisco IOS de test pour le projet 6NLG

Ces fichiers ont ete rediges synthetiquement pour **tester le parseur**. Ils ne
sont ni des exports d'equipements reels, ni des donnees collectees independamment
par un tiers. Ne pas les presenter comme une preuve de generalisation a des
equipements reels.

## Scenarios

1. `01_VLAN_ACL/R-LAB-VLAN-ACL.cfg` : sous-interfaces 802.1Q, ACL et route par defaut.
2. `02_OSPF_BGP/R-LAB-OSPF-BGP.cfg` : OSPF, eBGP, prefix-list et route-map.
3. `03_DHCP_NAT_SSH/R-LAB-DHCP-NAT-SSH.cfg` : serveur DHCP, NAT/PAT, acces SSH et logs.

Les plages publiques d'adresses sont exclusivement les blocs documentaires
`192.0.2.0/24`, `198.51.100.0/24` et `203.0.113.0/24` (RFC 5737). Aucun secret
ou identifiant n'est fourni. Il s'agit de fixtures, **pas de configurations
completes a deployer** : notamment l'authentification SSH, les clefs, le materiel
et la politique de securite necessiteraient une preparation specifique.

## Utilisation sur Ubuntu/WSL

Extraire le ZIP dans le depot :

```bash
cd ~/projet-6nlg/network-config-audit
mkdir -p data/holdout_synthetique_v66
unzip Cisco_6NLG_3_Configurations_Synthetiques_V66.zip -d data/holdout_synthetique_v66
```

Verifier les fichiers et executer l'audit, tout en gardant distinctes les
donnees synthetiques et les jeux de donnees reels :

```bash
find data/holdout_synthetique_v66 -type f -name '*.cfg'
PYTHONPATH=parsers python3 scripts/validate_holdout_v66.py \
  data/holdout_synthetique_v66 \
  --baseline-dir data/advanced_cases \
  --baseline-dir data/pybatfish_full \
  --baseline-dir data/c4geeks \
  --baseline-dir data/validation \
  --json-summary reports/holdout_synthetique_v66.json \
  --strict
```

`--strict` peut echouer sur une commande non reconnue : c'est une observation
utile pour ameliorer la couverture et **non** une raison de modifier artificiellement
les fichiers pour obtenir 3/3.

## Premier passage local sur le parseur V6.6

| Scenario | Statut | Commandes opaques | Recuperations |
| --- | --- | ---: | ---: |
| VLAN / ACL | `passed` | 0 | 0 |
| OSPF / BGP | `unmodeled_commands` | 3 | 0 |
| DHCP / NAT / SSH | `passed` | 0 | 0 |

Deux configurations sur trois passent sans inconnues. Le scenario OSPF/BGP
revele **une commande OSPF en sous-section** (`no passive-interface`) et
**deux occurrences dans les commandes de voisins BGP** (description et
route-map) que l'auditeur V6.6 signale comme non modelisees. Une route-map
est deja structuree ailleurs dans le resultat du parseur : il faut donc
examiner cette incoherence entre le parseur et l'auditeur de couverture,
sans supprimer la commande du test.

Ce bilan est reproduit sur le parseur disponible dans l'environnement de
preparation ; executer la commande ci-dessus dans le depot WSL pour verifier
le resultat avec la copie installee chez l'utilisateur.

Pour un test de generalisation independant, recueillir des exports supplementaires
d'une autre source autorisee, expurges de toute donnee sensible, puis faire
un nouveau passage strict.
