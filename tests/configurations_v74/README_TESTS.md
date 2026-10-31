# 6NLG — 6 configurations Cisco IOS pour la validation V73

Toutes les adresses publiques sont dans les plages de documentation RFC 5737 ; les secrets de démonstration sont fictifs. **Ne pas appliquer ces configurations sur des équipements réels.**

Importer chaque `.cfg` dans « Nouvelle analyse » avec **Cisco IOS · Configuration classique**. Lancer le parsing et la normalisation, puis l'audit CIS (profil L2). Pour les scénarios 01, 02, 03, 04 et 06, cocher « configuration complète » **uniquement pour ce test synthétique**. Pour 05, ne jamais cocher cette case. Pour les scénarios WAN, déclarer `GigabitEthernet0/0` comme interface externe si le formulaire le demande.

| Fichier | Anomalies attendues dans `network_coherence` V73 | Autres défauts volontairement présents |
|---|---|---|
| 01_ADRESSAGE_ROUTAGE_CONFLITS.cfg | `ROUTE_CONFLICT=REVIEW`, `INVALID_DEFAULT_GATEWAY=REVIEW`, `OVERLAPPING_INTERFACE_SUBNETS=REVIEW` | Deux routes par défaut et next-hop potentiellement récursif |
| 02_ACL_MASQUAGE_CONTRADICTIONS.cfg | `ACL_RULE_SHADOWING=FAIL`, `UNUSED_ACL=REVIEW`, `UNDEFINED_ACL_BINDING=FAIL` | ACL VTY qui refuse toutes les adresses avant de permettre une IP |
| 03_OSPF_BGP_INCOHERENCES.cfg | Aucun nouveau verdict de cohérence dédié attendu en V73 | OSPF MD5 sans clé, voisin BGP non directement connecté et pair iBGP/eBGP à vérifier ; comportement réel inconnu |
| 04_VLAN_NAT_DHCP_ANOMALIES.cfg | `OVERLAPPING_DHCP_POOLS=REVIEW` | VLAN 999 non déclaré, deux NAT statiques vers la même IP globale ; ces deux détections ne sont pas implémentées en V73 |
| 05_PARTIEL_AMBIGU_INCOMPLET.cfg | `UNDEFINED_ACL_BINDING=REVIEW`, non `FAIL` | Extrait incomplet ; les 39 verdicts CIS doivent rester `UNKNOWN` pour le catalogue de laboratoire |
| 06_REFERENCE_DURCIE_COMPLEXE.cfg | Aucun nouveau diagnostic de cohérence V73 | Configuration plus durcie, mais **pas** une référence 39/39 PASS : services NTP, SNMP et autres durcissements CIS absents |

## Résultats CIS observés avec le moteur local V73

Ces résultats sont des observations de la version testée, pas des vérités réseau universelles.

| Scénario | PASS | FAIL | UNKNOWN | N/A |
|---|---:|---:|---:|---:|
| 01 | 5 | 21 | 3 | 10 |
| 02 | 7 | 18 | 4 | 10 |
| 03 | 4 | 24 | 4 | 7 |
| 04 | 4 | 21 | 4 | 10 |
| 05 (partiel) | 0 | 0 | 39 | 0 |
| 06 | 21 | 11 | 1 | 6 |

## Interprétation

Les 39 contrôles CIS et les diagnostics de cohérence sont des familles de résultats différentes. Un `PASS` CIS ne garantit pas l'absence de conflit de VLAN ou de NAT. `REVIEW` signifie qu'il faut valider le contexte (VRF, topologie, routes récursives, etc.). Les erreurs OSPF/BGP et VLAN/NAT que V73 ne détecte pas encore constituent les prochains cas de développement, **pas** des échecs du parser.

## Commandes de validation locale

Depuis la racine de `network-config-audit` :

```bash
export PYTHONPATH="$PWD:$PWD/parsers"
python -m unittest tests.test_network_coherence tests.test_cis_network_phase12 tests.test_cis39_holdout -v
```
