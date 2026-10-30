# 6NLG — Mise à jour de l'interface uniquement

Cette archive modifie UNIQUEMENT les fichiers suivants :

- `webapp/templates/index.html`
- `webapp/static/css/cis_audit.css`
- `webapp/static/css/cis_pipeline.css`
- `webapp/static/js/cis_audit.js`

Elle ne modifie **aucun** parseur, normaliseur, benchmark, audit_engine,
route Flask ou module Juniper. Elle fonctionne avec l'API CIS de phase 8
(`POST /api/cis/audit`) qui retourne `report`, `pipeline`, `summary`,
`downloads` et `html_preview`.

Les rapports HTML des étapes parsing, normalisation et synthèse sont générés
dans le navigateur depuis les données `pipeline` déjà produites par l'API.
Les deux PDF et les verdicts CIS restent produits par le backend existant.
Si une API récente fournit déjà les rapports HTML par URL, l'interface utilise
directement ces rapports, sans les recréer dans le navigateur.

## Installation sur l'original, actuellement nommé -ancien

Dans WSL, quitter l'ancien environnement activé (après déplacement du dossier) :

```bash
deactivate
hash -r
cd ~/projet-6nlg/network-config-audit-ancien
```

Sauvegarder l'interface, puis extraire le ZIP **interface seule** :

```bash
cp -a webapp webapp_sauvegarde_avant_ui
unzip -oq /mnt/c/Users/LENOVO/Downloads/NetAudit_6NLG_Interface_Seulement.zip -d .
```

Nettoyage optionnel des anciens actifs non utilisés :

```bash
rm -f webapp/static/css/app.css webapp/static/js/app.js
```

Il n'est PAS nécessaire de recopier le ZIP de projet complet.

Le répertoire a été déplacé, ce qui peut casser les chemins internes de son
ancien environnement `.venv`. Créer un environnement neuf sans supprimer
l'ancien :

```bash
python3 -m venv .venv-interface
source .venv-interface/bin/activate
python3 -m pip install -r requirements-web.txt
PYTHONPATH=parsers:.:scripts python3 -m webapp
```

L'interface est disponible sur `http://127.0.0.1:5050`.

## Portée de la mise à jour

Le seul formulaire appelle toujours les trois étapes Python de l'API :
parsing, normalisation, CIS. Les rapports HTML côté navigateur sont des vues
des compteurs et parties exposés par cette API ; ils ne prétendent pas
contenir des structures détaillées que l'API n'envoie pas.

La case « configuration complète » est supprimée de la page ; le formulaire
n'envoie plus `assume_complete`. Les absences restent UNKNOWN selon le moteur
en mode non-complet. Les commandes explicitement non conformes peuvent
toujours produire FAIL.
