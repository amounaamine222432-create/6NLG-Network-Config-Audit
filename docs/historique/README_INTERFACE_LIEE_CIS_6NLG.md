# NetAudit 6NLG — Interface fusionnée et parcours CIS lié

## Ce que corrige cette version

L'ancienne interface de Parsing / Normalisation reste complète : import
de plusieurs configurations (y compris 3 fichiers), Cisco / Juniper,
onglets « Parsing JSON », « Normalisation IR », inventaire, rapport technique
HTML complet et exports JSON.

**Le module CIS ne demande plus de second import.** Après l'analyse globale,
il reçoit en mémoire la référence aux fichiers Cisco acceptés. Si plusieurs
routeurs sont analysés, on sélectionne lequel auditer. Le même objet `File`
est ensuite transmis à la route CIS existante.

Le parcours présenté est désormais :

1. **Parsing**, déjà effectué par le tableau de bord ; son **rapport HTML
   technique complet d'origine** est conservé, sans générer de deuxième
   `01_parsing.html` simplifié.
2. **Normalisation IR**, déjà effectuée ; l'IR JSON reste accessible et les
   rapports HTML de normalisation et de synthèse Parsing + IR restent
   disponibles.
3. **Audit CIS**, activé uniquement pour une configuration Cisco analysée ;
   comparaison aux 39 contrôles, détails de preuves, rapport HTML et PDF final.

Les verdicts du moteur CIS ne sont pas modifiés. Le module actuel `/api/cis/audit`
continue à reconstruire en mémoire les éléments de preuve à partir du même
fichier pour son propre calcul. Cette version lie **l'entrée et la
présentation des rapports**, sans changer les scripts ou faire passer un
ancien IR pour une nouvelle preuve de conformité.

## Contenu de l'archive (interface uniquement)

```text
webapp/templates/index.html
webapp/static/css/app.css
webapp/static/css/cis_audit.css
webapp/static/css/cis_pipeline.css
webapp/static/css/cis_bridge.css
webapp/static/js/app.js
webapp/static/js/cis_audit.js
README_INTERFACE_LIEE_CIS_6NLG.md
```

Le correctif n'inclut **aucun fichier du moteur** : pas de `webapp/app.py`,
pas de `audit_engine/`, `parsers/`, `normalizers/`, `scripts/`.

## Installation WSL — dépôt original

Télécharger `NetAudit_6NLG_Interface_Liee_Parsing_IR_Audit_CIS_V2.zip` dans
le dossier `Downloads` de Windows.

```bash
cd ~/projet-6nlg/network-config-audit-ancien

# Sauvegarde récupérable de l'interface avant remplacement.
tar -czf "../webapp_avant_fusion_liee_$(date +%Y%m%d_%H%M%S).tar.gz" webapp

# Décompresse uniquement les 7 fichiers d'interface et ce README.
unzip -o /mnt/c/Users/LENOVO/Downloads/NetAudit_6NLG_Interface_Liee_Parsing_IR_Audit_CIS_V2.zip -d .

# Quitter l'ancien environnement, si nécessaire.
deactivate 2>/dev/null || true
hash -r

# Conserver un environnement existant fonctionnel ; réparer seulement s'il est cassé.
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

Ouvrir `http://127.0.0.1:5050`, puis forcer le rechargement `Ctrl+Maj+R`.

## Test fonctionnel recommandé

1. Charger `router_compliant.cfg`, `router_non_compliant.cfg`,
   `router_partial.cfg` ensemble dans le tableau de bord Cisco.
2. Lancer l'analyse globale ; vérifier les JSON de parsing et d'IR et
   ouvrir le rapport technique complet.
3. Descendre vers « Audit CIS » ; le choix des trois routeurs doit apparaître
   automatiquement **sans second upload**.
4. Sélectionner le routeur souhaité et lancer l'audit. Vérifier que
   le premier lien HTML renvoie au rapport global existant, que la synthèse
   IR reste disponible et que le rapport CIS final est distinct.
5. Remplacer les fichiers dans la zone globale : les anciens résultats CIS
   doivent se masquer pour éviter une confusion de preuves.

## Vérification du correctif

- 26 tests Flask (ancienne interface + CIS/PDF) : **OK**.
- Test de liaison DOM (3 fichiers dont 1 rejeté, passage du même `File`,
  conservation du rapport technique, invalidation à nouveau chargement) :
  **OK**.
- `node --check` pour les deux scripts JavaScript : **OK**.

La batterie Juniper complète n'a pas été exécutée dans la copie de travail
réduite, dépourvue du normaliseur Junos original ; aucun composant Juniper
n'est modifié dans ce correctif.
