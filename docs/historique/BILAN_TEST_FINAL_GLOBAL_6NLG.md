# Projet 6NLG — Test d'intégration final sur une configuration Cisco IOS globale

## Objet

Valider le circuit complet de l'interface Flask existante : import d'une
configuration IOS synthétique, parsing, normalisation IR, génération du bilan
HTML et contrôle de non-divulgation des secrets.

Le fichier `R-6NLG-GLOBAL-TEST-01.cfg` simule un équipement comprenant :

- 8 interfaces (LAN/VLAN, WAN, management, OSPF et Loopback) ;
- 3 VLAN, 1 VRF, 1 groupe HSRP ;
- 2 routes statiques, 1 processus OSPF, 1 processus BGP ;
- 2 ACL, 1 prefix-list et 1 route-map ;
- 1 règle NAT/PAT, 1 pool DHCP ;
- SNMP, Syslog, NTP et VTY/SSH.

## Résultat observé (copie de développement)

| Contrôle | Résultat |
| --- | --- |
| Import Flask | HTTP 200 |
| Parsing | Effectué |
| Normalisation IR | Effectuée |
| Génération et prévisualisation HTML | HTTP 200 |
| Équipements | 1 |
| Interfaces | 8 |
| OSPF / BGP | 1 / 1 |
| ACL / routes statiques | 2 / 2 |
| NAT / DHCP / HSRP / VRF | 1 / 1 / 1 / 1 |
| VLAN / prefix-list / route-map | 3 / 1 / 1 |
| Globales inconnues / sections opaques / plateforme inconnue | 0 / 0 / 0 |
| Secrets factices retrouvés dans les exports | 0 |
| Vérifications du script final | **53/53 réussies** |

Les documents comportent les sections/interfaces/protocoles attendus et les
masques IPv4 sont représentés en CIDR dans l'IR. L'IR laisse l'état
opérationnel des interfaces indéterminé, ce qui est correct pour une analyse
de configuration sans accès réseau.

## Reproduire dans le dépôt WSL existant

Copier le fichier `.cfg` et le script `.py` à la racine du dépôt :

```bash
cd ~/projet-6nlg/network-config-audit
source .venv/bin/activate
python3 test_final_global_6nlg.py
```

Dans l'interface Flask, importer `R-6NLG-GLOBAL-TEST-01.cfg` puis examiner
la **Vue complète** (Parsing JSON, Normalisation IR, Rapport HTML).

## Limites du verdict

- **Test synthétique de régression :** ce fichier ne constitue pas un nouveau
  jeu indépendant de validation (*holdout*). Il a déjà servi à vérifier
  l'intégration de l'interface.
- **Pas de certification constructeur :** une syntaxe IOS 15.x reconnue
  n'atteste pas le modèle réel ni la compatibilité matérielle.
- **Pas de preuve d'exploitation :** l'état des interfaces, des voisinages
  OSPF/BGP, de la journalisation ou de l'application effective des ACL ne peut
  pas être déduit de la configuration seule.
- **Pas de couverture universelle :** zéro commande inconnue dans ce fichier
  ne démontre pas que le parseur, l'IR et le HTML couvrent toutes les versions
  ou commandes Cisco IOS.
- Les identifiants et secrets inclus dans ce fichier sont des marqueurs de
  démonstration. **Ne jamais déployer cette configuration sur un routeur réel.**

**Verdict : le flux Parsing -> IR -> Rapport HTML est validé pour ce cas
global précis. Le moteur d'audit exhaustif et la compatibilité multi-modèles
restent des étapes distinctes.**
