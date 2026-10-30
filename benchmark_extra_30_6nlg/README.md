# 6NLG — complément de benchmark de 30 configurations IOS 15

Cette archive ajoute 30 configurations synthétiques en six familles (ACL, ROUTING, BGP, DHCP_NAT, VLAN_VRF, STATIC), chacune avec des **assertions explicites** de référence, séparées pour le parsing et l'IR. Les références viennent des paramètres des scénarios et non des sorties du parseur. Une revue humaine reste nécessaire.

Depuis `~/projet-6nlg/network-config-audit` :

```bash
unzip -o /mnt/c/Users/LENOVO/Downloads/6NLG_PATCH_VALIDATION_BENCHMARK_30.zip
export PYTHONPATH="$PWD:$PWD/parsers:$PWD/scripts"
python3 benchmark_extra_30_6nlg/evaluate.py --project .
python3 final_validation_6nlg/export_final_validation.py --project .
python3 -m unittest tests.test_cisco_normalizer tests.test_cis15_engine tests.test_cisco_coverage_v67 tests.test_banner_vty_pipeline_regression tests.test_eigrp_acl_options_v67 -v
```

Le programme retourne un code de sortie différent de zéro si une assertion échoue, avec détails dans `benchmark_extra_30_6nlg/results.json`.

Résultat sur la copie de code utilisée : **30 scénarios, 158 assertions de valeurs (73 parsing et 85 IR), zéro écart**. Les scénarios sont relativement petits et conçus pour tester des valeurs clés : cette mesure ne constitue **pas** un F1-score global du logiciel. Aucun script `parsers/`, `normalizers/` ou `audit_engine/` n'a été modifié dans ce correctif.

Le cas `01_R-FINAL-HARDENED.cfg` a été corrigé pour autoriser `10.60.10.100` dans l'ACL VTY de gestion, dans le LAN, au lieu de `192.0.2.10` bloqué par l'ACL WAN.

### Test de non-régression

Les 31 tests ciblés ci-dessus passent dans la copie disponible. La suite de 146 tests a également été tentée mais ne peut pas être validée intégralement dans la copie fournie : plusieurs jeux de données dans `data/advanced_cases/` et `data/cis_phase5/` sont absents. Relancer la suite complète sur votre dépôt Ubuntu disposant de tous les jeux de test :

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```
