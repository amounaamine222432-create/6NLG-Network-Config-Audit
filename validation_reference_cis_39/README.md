# 6NLG — 3 configurations Cisco IOS 15 complètes (laboratoire)

Trois fichiers `.cfg` conformes au sous-ensemble **local** des 39 contrôles CIS :

1. `R-CIS39-REFERENCE.cfg` : référence sécurisée ; attendu 37 PASS + 2 N/A.
2. `R-CIS39-BRANCH-SECURE.cfg` : référence avec deux serveurs NTP authentifiés ; attendu 37 PASS + 2 N/A.
3. `R-CIS39-CONTROLLED-RISKS.cfg` : neuf défauts intentionnels (SSH, VTY, NTP,
   BGP, SNMP, Syslog et routage par la source) ; attendu 28 PASS + 9 FAIL + 2 N/A.

## Installer et exécuter dans la racine de ton dépôt WSL

```bash
unzip -n /mnt/c/Users/LENOVO/Downloads/6NLG_3_CONFIGS_COMPLETES_CIS_V68.zip
source .venv/bin/activate
export PYTHONPATH="$PWD:$PWD/parsers:$PWD/scripts"
python3 validation_reference_cis_39/run_validation.py .
```

Résumé sous Windows :

```bash
explorer.exe "$(wslpath -w validation_reference_cis_39/export/RESUME_VALIDATION.html)"
```

Le script exporte pour chaque `.cfg` les trois phases en **JSON et HTML** :
parsing, normalisation IR et audit CIS, et vérifie les 39 verdicts attendus.

## Résultats sur la copie locale du moteur V68

Les 3 tests ont réussi : **117/117 comparaisons ciblées**, sans commande globale
non parsée et sans section opaque reconnue par les diagnostics du moteur.

Attention : les *PASS* ne démontrent pas une certification CIS officielle ni
une politique sécurisée prête pour la production. Les identifiants, adresses
et secrets sont des données factices de laboratoire et ne sont pas conçus
pour être déployés. Les deux NOT_APPLICABLE concernent SNMP RW classique absent
et TTY absent ; ne pas les compter parmi les PASS.

La configuration `R-CIS39-CONTROLLED-RISKS.cfg` est volontairement non sûre.
Ne jamais la déployer sur un équipement réel.
