# NetAudit — Interface Web Flask pour le dépôt existant 6NLG

Cette archive **ajoute une interface moderne directement à ton projet existant**
`~/projet-6nlg/network-config-audit`. Elle **ne remplace pas** le parseur Cisco,
le normaliseur IR, le schéma, les scripts d'audit ni les tests déjà présents.

## 1. Installation dans ton dépôt WSL Ubuntu

```bash
cd ~/projet-6nlg/network-config-audit

# Contrôle non destructif : la destination ne doit pas déjà exister.
test ! -e webapp && echo "OK : module webapp absent, import possible"

# Adapte le nom du ZIP si ton navigateur l'a renommé.
unzip "/mnt/c/Users/LENOVO/Downloads/6NLG_Flask_Modern_Dashboard.zip" -d .

# Créer un environnement Python isolé pour Flask.
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements-web.txt

# Démarrer le serveur Web local.
python3 -m webapp
```

Puis ouvre **http://localhost:5050** dans Chrome/Edge sur Windows.
L'application écoute uniquement sur `127.0.0.1` et n'expose pas ton serveur WSL
sur le réseau local.

Si `.venv` existe déjà dans le dépôt, active-le directement sans le recréer :

```bash
source .venv/bin/activate
python3 -m pip install -r requirements-web.txt
python3 -m webapp
```

Si `python3 -m venv` échoue sur Ubuntu 22.04 à cause d'`ensurepip`, installer
le paquet système correspondant avec `sudo apt install python3-venv`, puis
recommencer. Pour arrêter le serveur : `Ctrl+C`.

## 2. Éléments ajoutés

```text
network-config-audit/
├── parsers/                    # déjà présent, inchangé
├── normalizers/                # déjà présent, inchangé
├── schemas/                    # déjà présent, inchangé
├── scripts/                    # déjà présent, inchangé
├── tests/                      # déjà présent, inchangé
├── webapp/                     # NOUVEAU
│   ├── __init__.py
│   ├── __main__.py
│   ├── app.py                   # routes Flask, sécurité, intégration
│   ├── templates/index.html    # tableau de bord
│   ├── static/css/app.css      # thème responsive
│   ├── static/js/app.js        # upload et résultats dynamiques
│   └── tests/test_webapp.py    # tests spécifiques à l'interface
├── requirements-web.txt       # NOUVEAU
└── README_WEB_FLASK_6NLG.md   # NOUVEAU
```

Le navigateur téléverse les fichiers à Flask, qui invoque **les fonctions du
dépôt existant** :

1. `parse_cisco_ios` : extraction des interfaces, ACL, routage, services, etc.
2. `normalize_cisco_ios` : création de l'IR JSON.
3. `audit_text` : mesure de couverture, commandes opaques et dialecte.
4. `analyze_device` et `render_html` : contrôles statiques et rapport HTML.

Les liens de téléchargement produisent :

- un **rapport HTML** ouvrable ou imprimable en PDF depuis le navigateur ;
- un **résumé JSON** des constats statiques ;
- l'**IR JSON** généré par le normaliseur de ton projet.

## 3. Utilisation de l'interface

1. Accède au tableau de bord sur `localhost:5050`.
2. Glisse ou sélectionne jusqu'à **10 fichiers `.cfg` / `.txt`** Cisco IOS
   (au maximum 1 Mio par fichier).
3. Clique sur **Lancer l'analyse**.
4. Examine les onglets **Équipements**, **Contrôles de configuration** et
   **Couverture du parsing**.
5. Télécharge les rapports et l'IR JSON.

Si une configuration est inconnue, mal formée ou provient d'un dialecte
incompatible (ex. IOS XR), le navigateur indique le rejet de ce fichier sans
prétendre qu'il a été correctement normalisé. Un lot peut avoir des succès
et des rejets partiels.

**Important :** les indications `passed`, `globales=0`, `sous_sections=0` et
la reconnaissance de la syntaxe IOS ne prouvent pas le modèle exact, la
compatibilité matérielle, l'état opérationnel ou l'efficacité réelle des ACL.
Les directives MMI anciennes peuvent avoir une sémantique documentée sans
applicabilité vérifiée aux équipements actuels.

## 4. Tests

Avec le même environnement virtuel activé :

```bash
cd ~/projet-6nlg/network-config-audit

# Suite existante : doit rester verte.
PYTHONPATH=parsers python3 -m unittest discover -s tests -p 'test_*.py' -v

# Nouveaux tests de l'intégration Flask.
python3 -m unittest discover -s webapp/tests -p 'test_*.py' -v
```

Les tests de l'interface couvrent : import simple et multiple, parsing et IR,
rapport HTML/JSON, absence de secret SNMP dans les exports, validation des
extensions, limites de taille, CSRF, protection des liens, rejet d'IOS XR.

## 5. Confidentialité et limites

- Les **configurations brutes restent en mémoire** pendant le traitement.
  Aucun fichier brut n'est archivé par cette interface.
- Le rapport expurgé et les données IR sont mis en cache en mémoire pour le
  téléchargement pendant **30 minutes** (ou jusqu'au redémarrage).
- Un IR peut contenir des **adresses IP, interfaces et noms d'équipement**.
  Avant de le partager, vérifie sa politique de confidentialité.
- Le serveur est prévu **pour usage local sur un PC**, sans authentification
  multi-utilisateurs. Il ne doit pas être exposé directement à Internet.
- L'interface utilise **Waitress**, pas le serveur de développement Flask.
- Proxy et SD-WAN apparaissent comme modules futurs, **non implémentés**.
- Les constats actuels sont des **audits statiques déclaratifs** ; ils ne
  remplacent pas les tests réseau ni Batfish/pyATS exécutés sur équipement.

## 6. Paramètres facultatifs

```bash
# Choisir un autre port local.
NETAUDIT_PORT=5051 python3 -m webapp

# Définir une clé de session stable via un gestionnaire de secrets si besoin.
# Ne jamais placer la clé dans Git.
NETAUDIT_SECRET_KEY='a-strong-random-value' python3 -m webapp
```

Pour préparer un futur déploiement partagé, prévoir authentification,
HTTPS, gestion des accès, persistance chiffrée, quotas, logs sans secrets
et processus de revue des règles avant toute mise en production.
