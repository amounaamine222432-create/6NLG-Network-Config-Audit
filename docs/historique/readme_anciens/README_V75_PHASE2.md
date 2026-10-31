# Correctif 6NLG V75 — Cohérence OSPF / BGP / VLAN / NAT

Ce paquet remplace `audit_engine/network_coherence.py` et ajoute `tests/test_network_advanced_v75.py`. Il est compatible avec la V73. Aucune règle ou décision du moteur CIS 39 n'est modifiée.

## Nouveaux diagnostics hors CIS

| Identifiant | Preuve recherchée | Verdict prudent |
|---|---|---|
| OSPF_MD5_KEY_COHERENCE | Interface avec mode message-digest mais sans identifiant de clé locale dans l'IR | REVIEW ; jamais FAIL sans contexte opérationnel |
| BGP_REMOTE_AS_COHERENCE | AS explicite hors plage 1..4294967295, ou AS absent | FAIL si invalide explicitement ; REVIEW si absent |
| BGP_PEER_REACHABILITY | IP du voisin hors des réseaux directement connectés identifiés | REVIEW ; routes récursives/IGP peuvent être légitimes |
| UNDECLARED_ACCESS_VLAN | Port access dans un VLAN autre que 1 absent de l'inventaire local | FAIL uniquement si configuration déclarée complète ET inventaire VLAN présent ; sinon REVIEW |
| NAT_STATIC_GLOBAL_COLLISION | Deux NAT statiques d'adresse entière (sans ports) avec le même inside global et inside local différents | FAIL |

Ces constats contiennent des repères de source quand l'IR en fournit. Ils ne constituent pas une preuve de fonctionnement réel ou une certification CIS. Le moteur ne tente jamais de se connecter aux équipements.

## Tests sur les scénarios V74

- `03_OSPF_BGP_INCOHERENCES.cfg` : `OSPF_MD5_KEY_COHERENCE=REVIEW` ; `BGP_PEER_REACHABILITY=REVIEW` ; `BGP_REMOTE_AS_COHERENCE=PASS` (AS valides en syntaxe, voisinage non prouvé).
- `04_VLAN_NAT_DHCP_ANOMALIES.cfg` : `UNDECLARED_ACCESS_VLAN=FAIL` et `NAT_STATIC_GLOBAL_COLLISION=FAIL` (fichier déclaré complet) ; `OVERLAPPING_DHCP_POOLS=REVIEW` reste présent.
- `05_PARTIEL_AMBIGU_INCOMPLET.cfg` : garder le mode partiel, aucun manque de définition ACL ne doit devenir FAIL ; les contrôles CIS restent UNKNOWN.
- `06_REFERENCE_DURCIE_COMPLEXE.cfg` : aucune collision NAT ni VLAN non déclaré, sans prétendre à la conformité 39/39.

## Installation Ubuntu WSL

```bash
cd ~/projet-6nlg/network-config-audit
unzip -o /mnt/c/Users/LENOVO/Downloads/6NLG_PHASE2_OSPF_BGP_VLAN_NAT_V75.zip
export PYTHONPATH="$PWD:$PWD/parsers"
python -m unittest tests.test_network_advanced_v75 tests.test_network_coherence tests.test_cis_network_phase12 tests.test_cis39_holdout tests.test_cis_source_evidence -v
```

Ensuite, redémarrer Flask et réimporter les scénarios 03 et 04 afin de recalculer de nouveaux rapports (les anciens HTML restent des snapshots de la V73).

## Limites assumées

- Le moteur ne calcule pas une adjacence OSPF ou BGP réelle et ne déduit pas la reachabilité totale depuis la seule configuration.
- Le diagnostic VLAN ne modélise pas entièrement VTP, DTP, VLAN appris ni l'état des trunks.
- Le diagnostic NAT se limite aux collisions explicites 1:1 ; les règles PAT à ports distincts sont exclues.
- Les valeurs héritées, la syntaxe opaque et les extraits incomplets exigent un contrôle humain.
