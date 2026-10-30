# NetAudit 6NLG — intégration Juniper Junos dans l'interface Flask existante

Ce ZIP **met à jour l'interface existante** du projet
`~/projet-6nlg/network-config-audit`. Il ne redéveloppe pas le parseur Cisco
et ne remplace pas les adaptateurs Juniper IR v2 déjà installés.

## Prérequis

- Le dépôt contient déjà `webapp/` (interface Flask V6.7) ;
- L'adaptateur Juniper v2.3 est installé :
  `normalizers/policy_ir_v2.py`, `normalizers/juniper_ir_adapter.py`,
  `normalizers/juniper_features_ir_v2.py`, `normalizers/junos_tree_loader.py`,
  `schemas/network_device_ir_v2.schema.json` ;
- Les dépendances `requirements-web.txt` et `requirements-juniper.txt`
  sont disponibles dans l'environnement virtuel.

## Fonctionnalités

1. Sélecteur **Cisco IOS / Juniper Junos** dans la même page moderne.
2. Import Cisco `.cfg/.txt` inchangé ; import Junos `.cfg/.conf/.txt` à
   accolades ou `display set`, ainsi que les exemples Markdown `.md`.
3. Analyse `/api/analyze` dirigée vers les normaliseurs existants selon le
   constructeur choisi — pas de détection automatique hasardeuse.
4. Quatre livrables séparés et visibles dans les onglets :
   **Parsing JSON expurgé**, **IR JSON v2**, **Résumé JSON**, **Bilan HTML**.
5. Bilan Juniper dédié : interfaces, IPv4/IPv6, BGP, OSPF, IS-IS,
   MPLS, EVPN, VRF, policies, statiques, zones et NAT SRX, compteurs
   de couverture v1/v2 **séparés**.

Les règles de contrôle Cisco existantes **ne sont pas appliquées** à Juniper.
Le bilan Juniper est un inventaire technique statique, pas une certification
de sécurité ni une preuve de sessions BGP/OSPF établies.

## Sauvegarder avant l'installation

La commande `git status` peut échouer si le dossier utilisateur n'est pas un
dépôt Git. Une sauvegarde par copies reste alors nécessaire :

```bash
cd ~/projet-6nlg/network-config-audit
source .venv/bin/activate
mkdir -p backups/webapp_before_juniper
cp webapp/app.py backups/webapp_before_juniper/app.py
cp webapp/templates/index.html backups/webapp_before_juniper/index.html
cp webapp/static/css/app.css backups/webapp_before_juniper/app.css
cp webapp/static/js/app.js backups/webapp_before_juniper/app.js
```

Placez le ZIP téléchargé dans `C:\Users\LENOVO\Downloads` puis, **depuis la
racine du dépôt**, exécutez :

```bash
unzip -o \
  '/mnt/c/Users/LENOVO/Downloads/6NLG_FLASK_CISCO_JUNIPER_INTEGRATION.zip' \
  -d .
python3 -m pip install -r requirements-web.txt
python3 -m pip install -r requirements-juniper.txt
```

Le ZIP contient uniquement les fichiers de l'interface à mettre à jour,
les nouveaux tests et cette notice. Il n'écrase pas le parseur Cisco ni
les normaliseurs Juniper. Les changements locaux divergents de ces fichiers
Flask doivent être fusionnés si l'équipe les a modifiés depuis V6.7.

## Tests

```bash
# Tests Flask Cisco (non régression) + Juniper :
PYTHONPATH=parsers:. python3 -m unittest discover \
  -s webapp/tests -p 'test_*.py' -v

# Tests du cœur de parsing/normalisation, à rejouer sur votre WSL :
PYTHONPATH=parsers:. python3 -m unittest discover \
  -s tests -p 'test_*.py' -v
```

Dans l'environnement de préparation de cette intégration : **19 tests Flask
réussis** (13 Cisco existants + 6 tests Juniper), et **93 tests Cisco cœur**
réussis après restauration locale du corpus de tests manquant. Les suites
du projet complet devront être rejouées sur votre WSL.

## Ouvrir l'interface

```bash
cd ~/projet-6nlg/network-config-audit
source .venv/bin/activate
PYTHONPATH=parsers:. python3 -m webapp
```

Ouvrez **http://127.0.0.1:5050** dans Windows :

- Sélectionnez **Juniper Junos / SRX** ;
- Importez `../juniper_sources/juniper-srx-config/srx110h-va/config.md`,
  ou un fichier Batfish `*.cfg`, ou un fichier Junosphere `*.conf` ;
- Lancez l'analyse ;
- Consultez **Vue complète**, **Parsing JSON**, **Normalisation IR** et
  **Rapport HTML**, puis téléchargez les livrables.

Pour basculer vers Cisco, changez simplement le sélecteur ; les fichiers
en attente sont effacés pour éviter de mélanger les constructeurs.

## Sécurité et limites

- Limites conservées : 10 fichiers et 1 Mio par fichier, CSRF, liens de
  téléchargement restreints à la session, durée du cache 30 minutes.
- Les parseurs tiers Juniper attendent un chemin : l'entrée brute est
  écrite dans un **répertoire temporaire privé et automatiquement supprimé**
  pendant la requête. Seuls l'IR expurgée et les rapports restent en mémoire
  pendant la session. Ceci diffère du traitement Cisco entièrement en mémoire.
- La vue « Parsing JSON » Juniper est volontairement une **projection
  expurgée** de l'arbre : noms d'interfaces, sections et protocoles ; aucune
  chaîne CLI brute ni valeur de mot de passe.
- `schema_valid_partial` est un statut normal : JSON valide mais couverture,
  validité constructeur et état opérationnel non prouvés.
- Ne publiez pas l'interface directement sur Internet sans authentification,
  HTTPS, restriction d'accès et durcissement supplémentaire.
