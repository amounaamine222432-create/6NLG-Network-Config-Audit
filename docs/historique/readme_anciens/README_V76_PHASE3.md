# 6NLG V76 — Interface et remédiation

Ce ZIP s'applique **après V75**. Il ne remplace ni le parser Cisco, ni les 39 règles CIS, ni les exports PDF.

## Fonctions ajoutées

1. Dans le rapport d'audit HTML, les repères `Lxx` des anomalies CIS et réseau ouvrent la section « Configuration importée » et ciblent la ligne numérotée. Les directives associées à une preuve CIS FAIL directe sont surlignées. Une ligne de contexte n'est pas présentée comme preuve définitive.
2. Dans l'interface, les repères des contrôles CIS deviennent des liens ouvrant le rapport à la ligne ciblée.
3. Pour les contrôles VTY, les exemples correctifs reprennent les plages VTY réelles lorsque leurs identifiants sont validés. Les autres exemples restent des modèles à adapter, non exécutables automatiquement.
4. Sous les résultats CIS, « Comparer avant/après » accepte une configuration corrigée `.cfg`/`.txt` (1 Mio max), réutilise la même API d'audit, le même profil CIS, la même hypothèse de complétude et les interfaces externes désignées. Il affiche les différences de verdicts CIS/réseau, le nombre de FAIL→PASS et de PASS→FAIL et un lien vers le rapport HTML après correction.
5. Le résumé des FAIL HTML contient les repères source et les exemples IOS contextualisés déjà disponibles, en plus des constats et recommandations. Toutes les données sont échappées pour prévenir l'injection HTML.

## Limites

- Les configurations importées ne sont pas corrigées automatiquement et aucune commande n'est envoyée au routeur.
- Le nouveau fichier avant/après est réévalué par le moteur ; l'interface affiche une alerte si les hostnames divergent, mais ne vérifie pas l'identité physique du routeur.
- Seul `FAIL → PASS` est compté comme correction confirmée sur la configuration. `UNKNOWN` et `NOT_APPLICABLE` ne sont pas comptés comme des corrections.
- Les lignes du rapport sont des aperçus expurgés, pas une copie des commandes sensibles.

## Installation / validation WSL

```bash
cd ~/projet-6nlg/network-config-audit
unzip -o /mnt/c/Users/LENOVO/Downloads/6NLG_PHASE3_INTERFACE_REMEDIATION_V76.zip
source .venv/bin/activate
export PYTHONPATH="$PWD:$PWD/parsers"
python -m unittest tests.test_cis_phase3_v76 tests.test_cis_export_features tests.test_cis_source_evidence tests.test_network_advanced_v75 tests.test_cis39_holdout -v
python -m unittest discover -s webapp/tests -p 'test_*.py' -v
node --check webapp/static/js/cis_audit.js
python -m flask --app webapp.app run --host 127.0.0.1 --port 5000
```

Dans le navigateur, importer `02_ACL_MASQUAGE_CONTRADICTIONS.cfg`, lancer l'analyse et l'audit CIS, ouvrir un repère de preuve, puis importer une version corrigée dans « Comparer avant/après ».
