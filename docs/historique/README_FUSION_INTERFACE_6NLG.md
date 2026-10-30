# NetAudit 6NLG — Fusion de l'ancienne interface et de l'audit CIS

Ce correctif est **exclusivement visuel**. Il restaure le tableau de bord
historique de NetAudit et ajoute le module d'audit CIS Cisco IOS 15.

## Fonctions conservées

- Import **multiple** de configurations (dont les 3 fichiers du test global),
  avec choix Cisco IOS / Juniper Junos.
- Exploration dans l'interface : Vue complète, Équipements, **Parsing JSON**,
  **Normalisation IR**, contrôles statiques, couverture et aperçu HTML.
- Téléchargements indépendants : résumé JSON, parsing JSON, IR JSON,
  rapport technique HTML.
- Endpoints du projet d'origine `/api/analyze`, `/api/view/...` et
  `/api/download/...` conservés.

## Module ajouté

- Import d'un fichier Cisco IOS dans l'espace « Audit CIS ».
- Chaîne existante : parsing → normalisation IR → moteur CIS.
- Profil L1 / L2 ; interface(s) externe(s) optionnelle(s).
- Fiches des 39 contrôles : exigences, observations, preuves, analyse,
  risques, corrections et vérification.
- Rapports HTML par étape, synthèse HTML et deux PDF, **lorsque ces
  exports sont fournis par le serveur**. Avec l'API phase 8 antérieure,
  les HTML des étapes 1/2 sont générés côté navigateur uniquement à partir
  des comptages et de l'inventaire déjà produits par les scripts Python.
- Les résultats du moteur et les 39 verdicts ne sont pas recalculés ni modifiés.
- Le module conserve la prudence applicable aux extraits partiels :
  **UNKNOWN** en l'absence de preuve suffisante.

## Contenu de l'archive

```text
webapp/
  templates/index.html          # ancien tableau de bord + audit CIS
  static/css/app.css            # style historique restauré
  static/css/cis_audit.css      # fiches de contrôles
  static/css/cis_pipeline.css   # rapports des trois étapes
  static/css/cis_bridge.css     # adaptation visuelle commune
  static/js/app.js              # fonctions historiques /api/analyze
  static/js/cis_audit.js        # module actuel /api/cis/audit
README_FUSION_INTERFACE_6NLG.md
```

**Aucun fichier `webapp/app.py`, `audit_engine/`, `parsers/`,
`normalizers/` ou `scripts/` n'est inclus.**

## Installation sur Ubuntu / WSL

Installer dans le dépôt historique **qui contient déjà les deux routes API**.
Ne décompressez pas `NetAudit_6NLG_Projet_Complet_3_Etapes.zip` par-dessus
le projet, car cette archive contient aussi le moteur et d'autres fichiers.

```bash
cd ~/projet-6nlg/network-config-audit-ancien

# Sauvegarde intégrale et récupérable de l'interface actuelle.
tar -czf "../webapp_avant_fusion_$(date +%Y%m%d_%H%M%S).tar.gz" webapp

# Adapter le nom si l'archive a été téléchargée ailleurs.
unzip -l /mnt/c/Users/LENOVO/Downloads/NetAudit_6NLG_Fusion_Ancien_Dashboard_Audit_CIS.zip
unzip -o /mnt/c/Users/LENOVO/Downloads/NetAudit_6NLG_Fusion_Ancien_Dashboard_Audit_CIS.zip -d .

# Relancer en conservant l'environnement Python déjà valide du dépôt.
deactivate 2>/dev/null || true
hash -r

# Seulement si l'environnement local est cassé ou absent :
if [ ! -x .venv/bin/python3 ]; then
  if [ -d .venv ]; then
    mv .venv "../venv_invalide_$(date +%Y%m%d_%H%M%S)"
  fi
  /usr/bin/python3 -m venv .venv
fi

source .venv/bin/activate
python3 -m pip install -r requirements-web.txt
PYTHONPATH=parsers:.:scripts python3 -m webapp
```

Dans le navigateur : `http://127.0.0.1:5050/`.

1. En haut : charger **3 fichiers** dans l'ancien tableau de bord, utiliser
   les onglets « Parsing JSON » et « Normalisation IR », et télécharger le
   rapport technique.
2. Dans le menu latéral **Audit CIS** : charger une configuration Cisco IOS,
   lancer la chaîne et consulter le rapport d'audit final PDF.

Si le navigateur garde les anciennes ressources CSS/JS, actualiser avec
`Ctrl+Maj+R`.

## Tests de non-régression réalisés

- 26 tests Python ciblés : **OK** (interface historique et audit CIS).
- 3 fichiers dans `/api/analyze` : résultats de parsing et IR disponibles
  pour les 3.
- Vérification du chargement des ressources et des identifiants HTML/JS : OK.
- L'ensemble Juniper ne peut pas être testé dans l'archive de travail
  réduite, qui ne contient pas `normalizers.junos_tree_loader`. Cette
  dépendance existait dans le dépôt original ; aucun fichier Juniper ne
  figure dans ce correctif.
