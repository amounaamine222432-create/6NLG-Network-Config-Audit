# NetAudit 6NLG - Chaîne Cisco IOS intégrée et deux rapports PDF

## Objectif

L'interface `Chaîne Cisco + CIS` orchestre désormais une **seule exécution** :

1. **Parsing** - Reconnaissance des éléments Cisco IOS 15 dans la configuration.
2. **Normalisation IR** - Transformation des données reconnues dans l'IR et
   inventaire des parties couvertes ou non observées.
3. **Audit CIS** - Comparaison de 39 contrôles sélectionnés du benchmark CIS
   Cisco IOS 15 v4.1.1 avec les valeurs structurées de l'IR.
4. **Rapports** - Génération de deux PDF distincts, plus les exports HTML et
   JSON préexistants du module CIS.

Une étape en échec empêche la finalisation des étapes suivantes. Le navigateur
affiche une progression globale durant la requête et confirme les trois étapes
une fois le serveur revenu avec les deux rapports ; il ne simule pas la durée
individuelle de chaque étape.

## Rapports

**Rapport 01 - Parsing et normalisation** : fichier, hash SHA-256, nombre
d'interfaces, OSPF/BGP, ACL, routes, NAT, éléments techniques expurgés,
inventaire parsing-vers-IR et limites de couverture. Ce rapport ne prononce
aucun verdict de conformité CIS.

**Rapport 02 - Audit CIS** : pour chacun des 39 contrôles, référence et page
documentaire, profil, exigence attendue, constat observé dans l'IR, statut
PASS/FAIL/UNKNOWN/NA, preuve structurée et action corrective éventuelle.
L'export JSON contient l'intégralité des preuves ; un extrait peut être
raccourci dans le PDF pour conserver la lisibilité des pages.

Ces PDF sont produits **en mémoire**. Les configurations brutes et les valeurs
de secrets ne sont pas incluses. Les téléchargements restent limités à la
session qui a produit le rapport (expiration du cache après 30 minutes).

## Mise à jour dans WSL

Vérifier et sauvegarder les fichiers personnalisés qui pourraient être
remplacés, puis à la racine de `~/projet-6nlg/network-config-audit` :

```bash
unzip -l /mnt/c/Users/LENOVO/Downloads/audit_cisco_ios_pipeline_2pdf_6nlg.zip
unzip /mnt/c/Users/LENOVO/Downloads/audit_cisco_ios_pipeline_2pdf_6nlg.zip
source .venv/bin/activate
python3 -m pip install -r requirements-web.txt
PYTHONPATH=parsers:.:scripts python3 -m unittest \
  webapp.tests.test_webapp \
  webapp.tests.test_webapp_cis_phase6 \
  webapp.tests.test_webapp_cis_pipeline_pdf -v
PYTHONPATH=parsers:.:scripts python3 -m webapp
```

Ouvrir `http://127.0.0.1:5050/#cis-audit`, sélectionner Cisco IOS, puis
importer un fichier `data/cis_phase5/*.cfg`. L'analyse complète et les deux
boutons **Télécharger PDF** apparaissent en bas du formulaire.

| Fichier | Profil | Complète | Interface externe | PASS / FAIL / UNKNOWN / N/A |
| --- | --- | --- | --- | --- |
| router_compliant.cfg | L2 | oui | GigabitEthernet0/0 | 36 / 0 / 0 / 3 |
| router_non_compliant.cfg | L2 | oui | GigabitEthernet0/0 | 2 / 33 / 0 / 4 |
| router_partial.cfg | L2 | **non** | *(vide)* | 1 / 0 / 38 / 0 |

Le formulaire classique « Importer & analyser » reste disponible pour les
analyses multi-fichiers et Juniper ; il n'est pas le chemin d'exécution CIS.
La nouvelle chaîne Cisco contient maintenant **ses propres étapes de parsing
et de normalisation** avant l'audit, au sein d'un seul parcours.

## Générer deux PDF de démonstration en ligne de commande

```bash
PYTHONPATH=parsers:.:scripts python3 scripts/export_cis_demo_pdf.py \
  data/cis_phase5/router_non_compliant.cfg \
  --profile L2 --assume-complete \
  --external-interface GigabitEthernet0/0
```

Les deux documents seront enregistrés sous `output/pdf/`.

## Portée et précautions

- `PASS` et `FAIL` n'existent que lorsque le contrôle dispose de faits
  suffisants ou lorsque la configuration est **explicitement déclarée complète**.
- `UNKNOWN` désigne une conclusion impossible : ce n'est **pas** un PASS.
- Le pourcentage présenté est limité aux contrôles `PASS + FAIL` décidés ;
  ce n'est pas une conformité globale au benchmark.
- Les règles et références sont celles du **catalogue de 39 contrôles du
  laboratoire**, et non de l'ensemble du benchmark CIS.
- Les commandes `show` et les contrôles de fonctionnement réel restent
  distincts et doivent être réalisés en lecture seule.

## Fichiers modifiés/ajoutés

`webapp/app.py`, `webapp/cis_dashboard.py`, `webapp/pdf_exports.py`,
`webapp/templates/index.html`, `webapp/templates/report_cis_ios.html`,
`webapp/static/js/cis_audit.js`, `webapp/static/css/cis_audit.css`,
`requirements-web.txt`, `scripts/export_cis_demo_pdf.py`,
`webapp/tests/test_webapp_cis_pipeline_pdf.py`, et un ajustement du test
`webapp/tests/test_webapp_cis_phase6.py`.
