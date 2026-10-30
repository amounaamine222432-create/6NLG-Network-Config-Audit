# 6NLG — Ajout des vues Parsing, IR et rapport HTML

Cette archive met à jour **uniquement l'application Flask existante** dans
`~/projet-6nlg/network-config-audit`. Le parseur, le normaliseur et les règles
d'audit Cisco IOS présents dans le dépôt ne sont pas remplacés.

## Ce qui change

- Après l'import d'un ou plusieurs fichiers `.cfg`/`.txt`, la **Vue complète**
  est affichée par défaut : **Parsing JSON** et **Normalisation IR** côte à
  côte, puis **Bilan HTML** dans la même page.
- Chaque section reste accessible dans son propre onglet. Les autres onglets
  (équipements, contrôles, couverture) sont conservés.
- Pour plusieurs configurations, le sélecteur permet de changer d'équipement
  dans les deux aperçus JSON.
- Des boutons permettent de télécharger le résumé, le parsing expurgé,
  l'IR normalisée et le rapport HTML.
- Les aperçus sont accessibles **uniquement dans la session qui a lancé
  l'analyse**, durant au plus 30 minutes et sans persistance des fichiers bruts.

**Sécurité :** la vue Parsing est une projection structurée volontairement
filtrée des résultats du parseur. Les mots de passe, secrets SNMP, commandes
brutes et lignes CLI inconnues ne sont pas exposés. Elle ne remplace pas
la configuration originale et ne certifie pas l'état opérationnel du réseau.

## Installation sous Ubuntu/WSL (dans le projet actuel)

Dans un terminal ouvert dans le projet :

```bash
cd ~/projet-6nlg/network-config-audit
```

Arrêter Flask si nécessaire avec `Ctrl+C`. Avant de remplacer les fichiers,
sauvegarder le dossier `webapp` dans un répertoire séparé :

```bash
cp -a webapp webapp_backup_avant_vues
```

Copier l'archive téléchargée dans le répertoire Windows `Downloads` puis :

```bash
unzip -l "/mnt/c/Users/LENOVO/Downloads/6NLG_MAJ_Vues_Parsing_IR_HTML.zip"
unzip -o "/mnt/c/Users/LENOVO/Downloads/6NLG_MAJ_Vues_Parsing_IR_HTML.zip" -d .
```

L'extraction crée/actualise uniquement les fichiers `webapp/` et ce README.
L'archive ne contient **aucun fichier de `parsers/`, `normalizers/` ou `scripts/`**.

## Validation et lancement

```bash
source .venv/bin/activate
python3 -m unittest discover -s webapp/tests -p 'test_*.py' -v
python3 -m webapp
```

Ouvrir l'URL locale affichée par Flask, importer un fichier Cisco IOS, puis
vérifier la **Vue complète**, les sélecteurs d'équipement et les téléchargements.

Si `.venv` n'existe pas, installer `python3-venv`, recréer l'environnement puis
installer les dépendances listées dans le `requirements-web.txt` existant.

Tests réalisés sur la copie de développement : 13 tests Flask et 93 tests
du moteur Cisco IOS réussis. Les versions présentes dans votre dépôt WSL
peuvent compter davantage de tests.
