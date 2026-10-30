# 6NLG — Validation de toute la chaîne sur 10 configurations

Pipeline : **fichier CFG → parsing Cisco IOS → normalisation IR → moteur CIS 39 contrôles**.

## Installer et lancer dans WSL depuis la racine du projet

```bash
unzip -n /mnt/c/Users/LENOVO/Downloads/6NLG_TEST_10_CONFIGS_CHAINE_COMPLETE.zip
export PYTHONPATH="$PWD:$PWD/parsers:$PWD/scripts"
python3 validation_chaine_10_6nlg/run_pipeline.py --project .
```

Les exports se trouvent dans `validation_chaine_10_6nlg/export/` :

- `parsing/` : 10 JSON et 10 HTML ;
- `ir/` : 10 JSON et 10 HTML ;
- `audit/` : 10 JSON et 10 HTML ;
- `RESUME_CHAINE_10.html` : sommaire navigable des 10 cas ;
- `resume.json` : synthèse exploitable par script.

Pour voir le rapport sous Windows :

```bash
explorer.exe "$(wslpath -w validation_chaine_10_6nlg/export/RESUME_CHAINE_10.html)"
```

## Résultats observés sur la copie V68

10 fichiers traités ; 30 JSON + 30 HTML ; 14/14 assertions ciblées.
Les deux grands routeurs sont exploratoires et ne disposent pas d'oracle global.
Les 39 statuts par fichier restent des verdicts du moteur (pas un label CIS officiel).

Les configurations comprennent deux routeurs longs (renforcé et risqué),
deux exemples EIGRP multi-processus, deux cas ACL WAN, deux cas VTY,
un cas NTP multi-serveur et un cas OSPF multi-zone.

Ne pas interpréter les `UNKNOWN` comme FAIL ou PASS ; ils représentent un
manque d'information exploitable. Les cas avec `complete_config=True` sont
des échantillons de laboratoire où l'absence de directive est interprétée
explicitement, et non une déclaration sur un équipement réel.
