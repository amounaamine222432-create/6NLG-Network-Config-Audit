# 6NLG — correctif ciblé du moteur CIS IOS 15 (V68)

## Modifications

- `audit_engine/cis15_phase5_checks.py` : association EIGRP processus/interface corrigée ; vérification de la définition d'ACL WAN ; distinction plus précise création/liaison d'ACL VTY ; couverture anti-usurpation par réseau englobant.
- `audit_engine/cis15_extended_checks.py` : vérification de la cohérence des identifiants de clés NTP référencées, définies et approuvées.
- `normalizers/cisco_normalizer.py` : enrichissement non secret des identifiants NTP dans l'IR.
- `schemas/network_device_ir_v1.schema.json` : schéma compatible avec les identifiants NTP.
- `tests/test_cis15_corrections_v68.py` : cinq nouveaux tests de non-régression.

**Aucun remplacement du parseur Cisco ou de l'interface Flask.**

## Installation WSL

Depuis `~/projet-6nlg/network-config-audit` :

```bash
mkdir -p backup_audit_v68
cp audit_engine/cis15_phase5_checks.py backup_audit_v68/
cp audit_engine/cis15_extended_checks.py backup_audit_v68/
cp normalizers/cisco_normalizer.py backup_audit_v68/
cp schemas/network_device_ir_v1.schema.json backup_audit_v68/
unzip -o /mnt/c/Users/LENOVO/Downloads/6NLG_CORRECTIF_MOTEUR_CIS_V68.zip
export PYTHONPATH="$PWD:$PWD/parsers:$PWD/scripts"
python3 -m unittest tests.test_cis15_corrections_v68 -v
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

## Vérification du benchmark parsing/IR

```bash
python3 benchmark_extra_30_6nlg/evaluate.py --project .
```

## Interprétation

- `UNKNOWN` reste volontairement possible lorsque la configuration n'est pas présumée complète.
- Une ACL WAN simplement référencée mais non définie ne produit plus `PASS` : `UNKNOWN` si extrait partiel, `FAIL` si configuration déclarée complète.
- L'authentification NTP doit relier les mêmes identifiants de clés entre le serveur, la définition et la liste de confiance pour produire `PASS` sur le contrôle de cohérence.
- Un refus WAN `deny ip any any` satisfait la condition étroite de blocage des sources réservées, **sans garantir la disponibilité réseau**.
- La séparation 1.2.4/1.2.5 reste volontairement prudente : une ACL restrictive non liée à une ligne VTY donne `UNKNOWN` pour sa finalité de gestion.
- Le catalogue et les autres règles CIS ne sont pas déclarés certifiés. Ce patch doit être testé sur votre dépôt complet ; seule une sélection de 36 tests et le benchmark de 30 cas ont été exécutés dans la copie disponible.
