# 6NLG - Correctif de lisibilité des preuves CIS

Ce correctif ajoute des extraits de **configuration IOS source expurgés** dans
les rapports HTML et PDF d'audit. Il ne modifie pas les verdicts et ne lance
aucun second parsing. La source est le `content` de l'upload déjà traité par
`parse_cisco_ios()` et `normalize_cisco_ios()`.

## Fichiers du correctif

- `webapp/cis_source_evidence.py` : recherche limitée aux commandes attendues
  par chaque contrôle, ligne exacte, masquage des secrets.
- `webapp/cis_dashboard.py` : enrichissement du constat après calcul CIS.
- `webapp/app.py` : passage du contenu source dans l'enrichisseur existant.
- `webapp/templates/report_cis_ios.html` : présentation HTML par exigence.
- `webapp/pdf_exports.py` : section COMMANDES SOURCE dans chaque contrôle.
- `tests/test_cis_source_evidence.py` : tests de sécurité et de provenance.

## Intégration

1. Conserver une sauvegarde et une branche Git propre.
2. Extraire le ZIP à la racine de `network-config-audit/` ; les chemins
   `webapp/` et `tests/` sont relatifs à cette racine.
3. Vérifier avec `git diff` les cinq fichiers applicatifs et le nouveau test.
4. Lancer :

   `python3 -m unittest discover -s tests -p 'test_*.py' -q`

   `python3 -m unittest discover -s webapp/tests -p 'test_*.py' -q`

   `python3 validation_reference_cis_39/run_validation.py .`

5. Produire le rapport avec la même configuration par le flux Flask habituel.

## Sens de la preuve affichée

Les commandes présentées sont des **extraits source associés à la famille de
contrôle**, et non une nouvelle décision de conformité. Pour les règles
contextuelles, plusieurs interfaces, ACL ou plages VTY peuvent apparaître :
le verdict demeure exclusivement celui du moteur CIS fondé sur l'IR.

La liste est volontairement limitée à sept lignes par règle. Les valeurs de
mot de passe, secrets BGP/NTP/AAA, communautés SNMP et bannières sont masquées.
Quand aucun extrait sûr n'est disponible, aucun texte de configuration n'est
inventé : le rapport indique qu'aucune commande correspondante n'est affichable.

## Vérification locale réalisée

- Compilation Python des modules modifiés : OK.
- Quatre tests ciblés de preuve et secret : OK.
- Sur `R-CIS39-CONTROLLED-RISKS.cfg` : AAA ligne 6 ; SSHv1 ligne 11 ;
  VTY SSH lignes 101/104 ; VTY autorisant Telnet lignes 106/109.
- Suite Flask complète : non exécutée ici (dépendance `flask` non disponible
  dans ce conteneur) ; **à exécuter dans le `.venv` du projet avant fusion**.
